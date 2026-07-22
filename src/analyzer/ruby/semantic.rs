//! Ruby lowering into the language-neutral executable-semantics IR.
//!
//! Ruby's surface syntax deliberately leaves several decisions to lexical or
//! runtime semantics (notably local-variable versus zero-argument calls and
//! block invocation).  This adapter lowers only tree-sitter-structured control
//! and calls, and records the remaining decisions as exact semantic gaps.

use tree_sitter::Node;

use crate::analyzer::semantic::cfg::{
    CleanupRegionId, CompletionKind, CompletionRequest, CompletionRoute, DriveError,
    ProcedureCfgBuilder, ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::{ProjectFile, RubyAnalyzer};
use crate::hash::{HashMap, HashSet};

const ADAPTER_VERSION: &[u8] = b"ruby-cfg-v1";

impl_program_semantics_provider!(RubyAnalyzer, RubySemanticLowerer);

#[derive(Default)]
struct BodyComponents<'tree> {
    protected: Vec<Node<'tree>>,
    rescues: Vec<Node<'tree>>,
    alternative: Option<Node<'tree>>,
    ensure: Option<Node<'tree>>,
}

fn body_components(node: Node<'_>) -> BodyComponents<'_> {
    let body = if node.kind() == "body_statement" {
        node
    } else {
        node.child_by_field_name("body")
            .filter(|body| body.kind() == "body_statement")
            .unwrap_or(node)
    };
    let mut parts = BodyComponents::default();
    for child in named_children(body) {
        match child.kind() {
            "rescue" => parts.rescues.push(child),
            "else" => parts.alternative = Some(child),
            "ensure" => parts.ensure = Some(child),
            "comment" | "empty_statement" => {}
            _ => parts.protected.push(child),
        }
    }
    parts
}

fn body_has_rescue_or_ensure(node: Node<'_>) -> bool {
    named_children(node)
        .into_iter()
        .any(|child| matches!(child.kind(), "rescue" | "ensure"))
}

fn ordinary_body_statements(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| {
            !matches!(
                child.kind(),
                "rescue" | "else" | "ensure" | "comment" | "empty_statement"
            )
        })
        .collect()
}

fn runtime_statement_children(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| !matches!(child.kind(), "comment" | "empty_statement"))
        .collect()
}

fn branch_statements(node: Node<'_>) -> Vec<Node<'_>> {
    if matches!(
        node.kind(),
        "then" | "else" | "do" | "body_statement" | "block_body"
    ) {
        runtime_statement_children(node)
    } else {
        vec![node]
    }
}

fn statement_definitely_abrupt(node: Node<'_>) -> bool {
    matches!(node.kind(), "return" | "break" | "next" | "redo" | "retry")
}

fn runtime_expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "assignment" | "operator_assignment" => {
            let mut result = node
                .child_by_field_name("left")
                .map(assignment_target_runtime_nodes)
                .unwrap_or_default();
            result.extend(children_by_field_name(node, "right"));
            return result;
        }
        "binary" => {
            let mut result = children_by_field_name(node, "left");
            result.extend(children_by_field_name(node, "right"));
            return result;
        }
        "unary" => return children_by_field_name(node, "operand"),
        "pair" => {
            let mut result = children_by_field_name(node, "key");
            result.extend(children_by_field_name(node, "value"));
            return result;
        }
        "call" => {
            let mut result = children_by_field_name(node, "receiver");
            if let Some(arguments) = node.child_by_field_name("arguments") {
                result.extend(runtime_expression_children(arguments));
            }
            return result;
        }
        "block" | "do_block" | "lambda" | "method" | "singleton_method" | "class" | "module"
        | "singleton_class" => return Vec::new(),
        _ => {}
    }
    named_children(node)
        .into_iter()
        .filter(|child| is_runtime_node(child.kind()))
        .collect()
}

fn assignment_target_runtime_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let mut nodes = Vec::new();
    let mut stack = vec![node];
    while let Some(target) = stack.pop() {
        match target.kind() {
            "call" => nodes.extend(children_by_field_name(target, "receiver")),
            "element_reference" => {
                let object_id = target
                    .child_by_field_name("object")
                    .map(|object| object.id());
                nodes.extend(children_by_field_name(target, "object"));
                nodes.extend(named_children(target).into_iter().filter(|child| {
                    Some(child.id()) != object_id && is_runtime_node(child.kind())
                }));
            }
            "left_assignment_list" | "destructured_left_assignment" | "rest_assignment" => {
                stack.extend(named_children(target).into_iter().rev());
            }
            "identifier" | "instance_variable" | "class_variable" | "global_variable"
            | "constant" | "scope_resolution" | "self" | "super" | "true" | "false" | "nil" => {}
            _ => {}
        }
    }
    nodes
}

fn assignment_target_dispatches(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(target) = stack.pop() {
        match target.kind() {
            "call" | "element_reference" => return true,
            "left_assignment_list" | "destructured_left_assignment" | "rest_assignment" => {
                stack.extend(named_children(target));
            }
            _ => {}
        }
    }
    false
}

fn call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("arguments")
        .map(runtime_expression_children)
        .unwrap_or_default()
}

fn first_runtime_named_child(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| is_runtime_node(child.kind()))
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn required_field<'tree>(node: Node<'tree>, field: &str) -> Result<Node<'tree>, RubyLoweringError> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

fn missing_field(node: Node<'_>, field: &str) -> RubyLoweringError {
    RubyLoweringError::Invalid(format!(
        "{} node at bytes {}..{} is missing structured field {field}",
        node.kind(),
        node.start_byte(),
        node.end_byte()
    ))
}

fn is_short_circuit_binary(source: &str, node: Node<'_>) -> bool {
    node.child_by_field_name("operator")
        .and_then(|operator| node_text(source, operator))
        .is_some_and(|operator| matches!(operator, "&&" | "and" | "||" | "or"))
}

fn is_runtime_node(kind: &str) -> bool {
    !matches!(
        kind,
        "comment"
            | "method_parameters"
            | "lambda_parameters"
            | "block_parameters"
            | "block_parameter"
            | "optional_parameter"
            | "keyword_parameter"
            | "splat_parameter"
            | "hash_splat_parameter"
            | "forward_parameter"
            | "destructured_parameter"
            | "exception_variable"
            | "hash_key_symbol"
            | "bare_symbol"
    )
}

fn is_runtime_leaf(kind: &str) -> bool {
    matches!(
        kind,
        "integer"
            | "float"
            | "rational"
            | "complex"
            | "true"
            | "false"
            | "nil"
            | "self"
            | "constant"
            | "instance_variable"
            | "class_variable"
            | "global_variable"
            | "simple_symbol"
            | "hash_key_symbol"
            | "bare_symbol"
            | "character"
            | "escape_sequence"
    )
}

struct LocalBindingCollection {
    timeline: LocalBindingTimeline,
    has_parameter_defaults: bool,
    work: SemanticWork,
}

struct ProcedureBindings {
    timeline: LocalBindingTimeline,
    has_parameter_defaults: bool,
}

#[derive(Clone, Default)]
struct LocalBindingTimeline {
    entry_bindings: HashSet<Box<str>>,
    activations: HashMap<Box<str>, usize>,
}

impl LocalBindingTimeline {
    fn is_active_at(&self, name: &str, source_byte: usize) -> bool {
        self.entry_bindings.contains(name)
            || self
                .activations
                .get(name)
                .is_some_and(|activation| *activation <= source_byte)
    }

    fn active_names_at(&self, source_byte: usize) -> Vec<&str> {
        let mut names = self
            .entry_bindings
            .iter()
            .map(Box::as_ref)
            .chain(
                self.activations
                    .iter()
                    .filter(|(_, activation)| **activation <= source_byte)
                    .map(|(name, _)| name.as_ref()),
            )
            .collect::<Vec<_>>();
        names.sort_unstable();
        names
    }
}

struct LocalBindingCollector<'source, 'request> {
    source: &'source str,
    timeline: LocalBindingTimeline,
    has_parameter_defaults: bool,
    work: SemanticWork,
    budget: &'request SemanticBudget,
    cancellation: &'request CancellationToken,
}

impl<'source, 'request> LocalBindingCollector<'source, 'request> {
    fn new(
        source: &'source str,
        budget: &'request SemanticBudget,
        cancellation: &'request CancellationToken,
    ) -> Self {
        Self {
            source,
            timeline: LocalBindingTimeline::default(),
            has_parameter_defaults: false,
            work: SemanticWork::default(),
            budget,
            cancellation,
        }
    }

    fn charge(&mut self, delta: SemanticWork) -> Result<(), RubyLoweringError> {
        let candidate = self.work.conservative_add(delta);
        if let Err(exceeded) = self.budget.check(candidate) {
            return Err(RubyLoweringError::Budget(exceeded, Box::new(candidate)));
        }
        self.work = candidate;
        Ok(())
    }

    fn visit(&mut self) -> Result<(), RubyLoweringError> {
        if self.cancellation.is_cancelled() {
            return Err(RubyLoweringError::Cancelled(Box::new(self.work)));
        }
        self.charge(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })
    }

    fn insert_entry_name(&mut self, name: &str) -> Result<(), RubyLoweringError> {
        if self.cancellation.is_cancelled() {
            return Err(RubyLoweringError::Cancelled(Box::new(self.work)));
        }
        if self.timeline.entry_bindings.contains(name) {
            return Ok(());
        }
        if self.timeline.activations.remove(name).is_none() {
            self.charge(SemanticWork {
                owned_text_bytes: name.len(),
                ..SemanticWork::default()
            })?;
        }
        self.timeline.entry_bindings.insert(name.into());
        Ok(())
    }

    fn insert_activation(
        &mut self,
        name: &str,
        source_byte: usize,
    ) -> Result<(), RubyLoweringError> {
        if self.cancellation.is_cancelled() {
            return Err(RubyLoweringError::Cancelled(Box::new(self.work)));
        }
        if self.timeline.entry_bindings.contains(name) {
            return Ok(());
        }
        if let Some(activation) = self.timeline.activations.get_mut(name) {
            *activation = (*activation).min(source_byte);
            return Ok(());
        }
        self.charge(SemanticWork {
            owned_text_bytes: name.len(),
            ..SemanticWork::default()
        })?;
        self.timeline.activations.insert(name.into(), source_byte);
        Ok(())
    }

    fn insert_entry_identifier(&mut self, node: Node<'_>) -> Result<(), RubyLoweringError> {
        if node.kind() == "identifier"
            && let Some(name) = node_text(self.source, node)
        {
            self.insert_entry_name(name)?;
        }
        Ok(())
    }

    fn insert_activation_identifier(&mut self, node: Node<'_>) -> Result<(), RubyLoweringError> {
        if node.kind() == "identifier"
            && let Some(name) = node_text(self.source, node)
        {
            self.insert_activation(name, node.start_byte())?;
        }
        Ok(())
    }

    fn collect_parameters(&mut self, node: Node<'_>) -> Result<(), RubyLoweringError> {
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            self.visit()?;
            match current.kind() {
                "identifier" => self.insert_entry_identifier(current)?,
                "optional_parameter"
                | "keyword_parameter"
                | "splat_parameter"
                | "hash_splat_parameter"
                | "block_parameter" => {
                    self.has_parameter_defaults |= current.kind() == "optional_parameter"
                        || (current.kind() == "keyword_parameter"
                            && current.child_by_field_name("value").is_some());
                    if let Some(name) = current.child_by_field_name("name") {
                        self.insert_entry_identifier(name)?;
                    }
                }
                "method_parameters"
                | "lambda_parameters"
                | "block_parameters"
                | "destructured_parameter" => {
                    stack.extend(named_children(current).into_iter().rev());
                }
                "forward_parameter" | "hash_splat_nil" => {}
                _ => {}
            }
        }
        Ok(())
    }

    fn collect_assignment(&mut self, node: Node<'_>) -> Result<(), RubyLoweringError> {
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            self.visit()?;
            match current.kind() {
                "identifier" => self.insert_activation_identifier(current)?,
                "left_assignment_list"
                | "right_assignment_list"
                | "destructured_left_assignment"
                | "rest_assignment"
                | "exception_variable" => {
                    stack.extend(named_children(current).into_iter().rev());
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn collect_pattern(&mut self, node: Node<'_>) -> Result<(), RubyLoweringError> {
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            self.visit()?;
            match current.kind() {
                "identifier" => self.insert_activation_identifier(current)?,
                "as_pattern" => {
                    if let Some(name) = current.child_by_field_name("name") {
                        self.insert_activation_identifier(name)?;
                    }
                    stack.extend(children_by_field_name(current, "value"));
                }
                "keyword_pattern" => {
                    if let Some(value) = current.child_by_field_name("value") {
                        stack.push(value);
                    } else if let Some(key) = current.child_by_field_name("key")
                        && let Some(name) = node_text(self.source, key)
                    {
                        self.insert_activation(
                            name.strip_suffix(':').unwrap_or(name),
                            key.start_byte(),
                        )?;
                    }
                }
                "splat_parameter" | "hash_splat_parameter" => {
                    if let Some(name) = current.child_by_field_name("name") {
                        self.insert_activation_identifier(name)?;
                    }
                }
                "variable_reference_pattern" | "expression_reference_pattern" => {}
                "array_pattern" | "find_pattern" | "hash_pattern" => {
                    let class_id = current.child_by_field_name("class").map(|class| class.id());
                    let children = named_children(current)
                        .into_iter()
                        .filter(|child| Some(child.id()) != class_id)
                        .collect::<Vec<_>>();
                    stack.extend(children.into_iter().rev());
                }
                "alternative_pattern" | "parenthesized_pattern" => {
                    stack.extend(named_children(current).into_iter().rev());
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn finish(self) -> LocalBindingCollection {
        LocalBindingCollection {
            timeline: self.timeline,
            has_parameter_defaults: self.has_parameter_defaults,
            work: self.work,
        }
    }
}

fn collect_local_bindings(
    source: &str,
    callable: Node<'_>,
    body: Node<'_>,
    inherited: Option<(&LocalBindingTimeline, usize)>,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<LocalBindingCollection, RubyLoweringError> {
    let mut collector = LocalBindingCollector::new(source, budget, cancellation);
    let parameters = callable_parameters(callable, body);
    if let Some(parameters) = parameters {
        collector.collect_parameters(parameters)?;
    }
    if matches!(callable.kind(), "lambda" | "block" | "do_block") && parameters.is_none() {
        for name in ["_1", "_2", "_3", "_4", "_5", "_6", "_7", "_8", "_9", "it"] {
            collector.insert_entry_name(name)?;
        }
    }
    if let Some((inherited, source_byte)) = inherited {
        for name in inherited.active_names_at(source_byte) {
            collector.insert_entry_name(name)?;
        }
    }

    let mut stack = vec![body];
    if let Some(parameters) = parameters.filter(|parameters| {
        parameters.start_byte() < body.start_byte() || parameters.end_byte() > body.end_byte()
    }) {
        stack.push(parameters);
    }
    while let Some(node) = stack.pop() {
        collector.visit()?;
        match node.kind() {
            "assignment" | "operator_assignment" => {
                if let Some(left) = node.child_by_field_name("left") {
                    collector.collect_assignment(left)?;
                }
            }
            "for" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    collector.collect_assignment(pattern)?;
                }
            }
            "rescue" => {
                if let Some(variable) = node.child_by_field_name("variable") {
                    collector.collect_assignment(variable)?;
                }
            }
            "match_pattern" | "test_pattern" | "in_clause" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    collector.collect_pattern(pattern)?;
                }
            }
            _ => {}
        }
        for child in named_children(node).into_iter().rev() {
            if child.id() != body.id()
                && matches!(
                    child.kind(),
                    "method"
                        | "singleton_method"
                        | "lambda"
                        | "block"
                        | "do_block"
                        | "class"
                        | "module"
                        | "singleton_class"
                )
            {
                continue;
            }
            stack.push(child);
        }
    }
    Ok(collector.finish())
}

fn callable_parameters<'tree>(callable: Node<'tree>, body: Node<'tree>) -> Option<Node<'tree>> {
    callable.child_by_field_name("parameters").or_else(|| {
        (callable.kind() == "lambda")
            .then(|| body.child_by_field_name("parameters"))
            .flatten()
    })
}

fn source_anchor_between(
    start_node: Node<'_>,
    end_node: Node<'_>,
    occurrence: u32,
) -> Result<SourceAnchor, String> {
    let start_position = start_node.start_position();
    let end_position = end_node.end_position();
    let start = SourcePosition::new(
        u32::try_from(start_node.start_byte()).map_err(|_| "source start exceeds u32")?,
        u32::try_from(start_position.row).map_err(|_| "source start line exceeds u32")?,
        u32::try_from(start_position.column).map_err(|_| "source start column exceeds u32")?,
    );
    let end = SourcePosition::new(
        u32::try_from(end_node.end_byte()).map_err(|_| "source end exceeds u32")?,
        u32::try_from(end_position.row).map_err(|_| "source end line exceeds u32")?,
        u32::try_from(end_position.column).map_err(|_| "source end column exceeds u32")?,
    );
    let span = SourceSpan::new(start, end).map_err(|error| error.to_string())?;
    Ok(SourceAnchor::new(span, occurrence))
}

fn callable_source_anchor(
    callable: Node<'_>,
    body: Node<'_>,
    occurrence: u32,
) -> Result<SourceAnchor, String> {
    let start_position = callable.start_position();
    let start = SourcePosition::new(
        u32::try_from(callable.start_byte()).map_err(|_| "source start exceeds u32")?,
        u32::try_from(start_position.row).map_err(|_| "source start line exceeds u32")?,
        u32::try_from(start_position.column).map_err(|_| "source start column exceeds u32")?,
    );
    let end = if body.start_byte() > callable.start_byte() {
        let end_position = body.start_position();
        SourcePosition::new(
            u32::try_from(body.start_byte()).map_err(|_| "source end exceeds u32")?,
            u32::try_from(end_position.row).map_err(|_| "source end line exceeds u32")?,
            u32::try_from(end_position.column).map_err(|_| "source end column exceeds u32")?,
        )
    } else {
        start
    };
    let span = SourceSpan::new(start, end).map_err(|error| error.to_string())?;
    Ok(SourceAnchor::new(span, occurrence))
}

struct RubySemanticLowerer;

impl ProgramSemanticsLowerer for RubySemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("ruby", ADAPTER_VERSION)
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(
                b"ruby-intrafile-execution-defaults-v1",
            ),
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        ruby_capabilities()
    }

    fn lower(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        budget: &SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
        let specs = match enumerate_procedures(file, prepared, budget, cancellation)? {
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

        let mut bindings_by_procedure: Vec<ProcedureBindings> = Vec::with_capacity(specs.len());
        let mut binding_work = SemanticWork::default();
        for spec in &specs {
            let mut staged_budget = budget.clone();
            if let Err(exceeded) = staged_budget.charge(binding_work) {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: binding_work,
                });
            }
            let inherited = matches!(spec.kind, ProcedureKind::Lambda | ProcedureKind::Closure)
                .then(|| {
                    spec.lexical_parent
                        .and_then(|parent| bindings_by_procedure.get(parent.index()))
                        .map(|parent| (&parent.timeline, spec.callable.start_byte()))
                })
                .flatten();
            let collection = match collect_local_bindings(
                prepared.source(),
                spec.callable,
                spec.body,
                inherited,
                &staged_budget,
                cancellation,
            ) {
                Ok(collection) => collection,
                Err(RubyLoweringError::Cancelled(work)) => {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work: sum_lowering_work(binding_work, *work),
                    });
                }
                Err(RubyLoweringError::Budget(exceeded, work)) => {
                    let work = sum_lowering_work(binding_work, *work);
                    let exceeded = budget.check(work).err().unwrap_or(exceeded);
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
                Err(RubyLoweringError::Invalid(detail)) => {
                    return Err(SemanticProviderError::internal(detail));
                }
            };
            binding_work = sum_lowering_work(binding_work, collection.work);
            if let Err(exceeded) = budget.check(binding_work) {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: binding_work,
                });
            }
            bindings_by_procedure.push(ProcedureBindings {
                timeline: collection.timeline,
                has_parameter_defaults: collection.has_parameter_defaults,
            });
        }

        lower_procedure_batch(
            specs.iter().zip(&bindings_by_procedure),
            binding_work,
            budget,
            cancellation,
            |(spec, local_bindings), staged_budget, cancellation| {
                lower_procedure(
                    prepared,
                    spec,
                    &local_bindings.timeline,
                    local_bindings.has_parameter_defaults,
                    staged_budget,
                    cancellation,
                )
            },
        )
    }
}

fn ruby_capabilities() -> SemanticCapabilities {
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
        SemanticCapability::Calls,
        SemanticCapability::DynamicDispatch,
        SemanticCapability::CallableReferences,
        SemanticCapability::Values,
        SemanticCapability::GeneratorSuspension,
        SemanticCapability::DeferredExecution,
        SemanticCapability::ConcurrentSpawn,
        SemanticCapability::NonLocalControl,
        SemanticCapability::ResourceManagement,
    ] {
        builder = builder.partial(capability);
    }
    builder.build()
}

#[derive(Clone)]
struct ProcedureSpec<'tree> {
    id: ProcedureId,
    body: Node<'tree>,
    callable: Node<'tree>,
    empty_body: bool,
    locator: SemanticLocator,
    lexical_parent: Option<ProcedureId>,
    kind: ProcedureKind,
    properties: ProcedureProperties,
}

enum ProcedureEnumeration<'tree> {
    Complete(Vec<ProcedureSpec<'tree>>),
    ExceededBudget {
        exceeded: SemanticBudgetExceeded,
        work: SemanticWork,
    },
    Cancelled,
}

struct ProcedureEnumerationFrame<'tree> {
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
    declaration_path: usize,
    member_context: bool,
    singleton_context: bool,
    synthetic_body_scope: Option<SyntheticBodyScope>,
}

#[derive(Debug, Clone, Copy)]
struct SyntheticBodyScope {
    procedure: ProcedureId,
    callable_path: usize,
}

fn enumerate_procedures<'tree>(
    file: &ProjectFile,
    prepared: &'tree PreparedSyntaxTree,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<ProcedureEnumeration<'tree>, SemanticProviderError> {
    let mount = WorkspaceMountId::from_root(file.root());
    let path = WorkspaceRelativePath::try_from_path(file.rel_path())
        .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    let language = prepared.dialect();
    let root = prepared.tree().root_node();
    let file_anchor = source_anchor(root, 0).map_err(SemanticProviderError::invalid_identity)?;
    let file_name = file
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("ruby-source");
    let file_segment =
        DeclarationSegment::named(DeclarationSegmentKind::File, file_name, file_anchor, 0)
            .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;

    type SiblingKey = (usize, DeclarationSegmentKind, Option<Box<str>>);
    let mut specs = Vec::new();
    let mut siblings: HashMap<SiblingKey, u32> = HashMap::default();
    let mut declaration_paths = vec![DeclarationPathEntry {
        parent: None,
        segment: file_segment,
    }];
    let mut preflight = SemanticWork::default();
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: 0,
        member_context: false,
        singleton_context: false,
        synthetic_body_scope: None,
    }];

    while let Some(frame) = stack.pop() {
        if cancellation.is_cancelled() {
            return Ok(ProcedureEnumeration::Cancelled);
        }

        let mut child_path = frame.declaration_path;
        let mut child_member_context = frame.member_context;
        let mut child_singleton_context = frame.singleton_context;
        if let Some(segment_kind) = declaration_container_kind(frame.node) {
            let name = declaration_container_name(prepared.source(), frame.node);
            let ordinal =
                next_sibling_ordinal(&mut siblings, child_path, segment_kind, name.as_deref());
            let anchor =
                source_anchor(frame.node, 0).map_err(SemanticProviderError::invalid_identity)?;
            let segment = declaration_segment(segment_kind, name.as_deref(), anchor, ordinal)
                .map_err(SemanticProviderError::invalid_identity)?;
            child_path = push_declaration_path(&mut declaration_paths, child_path, segment);
            child_member_context = true;
            child_singleton_context = frame.node.kind() == "singleton_class";
        }

        let mut callable_body_scope = None;
        let mut self_callable_scope = None;
        let mut self_synthetic_scope = None;
        if let Some(shape) = callable_shape(prepared.source(), frame.node, frame.singleton_context)
        {
            let id = ProcedureId::try_from_index(specs.len())
                .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
            let name = callable_name(prepared.source(), frame.node, shape.kind);
            let ordinal = next_sibling_ordinal(
                &mut siblings,
                child_path,
                shape.segment_kind,
                name.as_deref(),
            );
            let anchor = callable_source_anchor(frame.node, shape.body, 0)
                .map_err(SemanticProviderError::invalid_identity)?;
            let segment = declaration_segment(shape.segment_kind, name.as_deref(), anchor, ordinal)
                .map_err(SemanticProviderError::invalid_identity)?;
            let mut segments = collect_declaration_path(&declaration_paths, child_path);
            segments.push(segment.clone());
            let declaration = DeclarationLocator::new(segments)
                .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
            let locator = SemanticLocator::new(
                mount,
                path.clone(),
                language,
                declaration,
                SemanticRole::Procedure,
                anchor,
            );
            let candidate = sum_lowering_work(preflight, procedure_identity_preflight(&locator));
            if let Err(exceeded) = budget.check(candidate) {
                return Ok(ProcedureEnumeration::ExceededBudget {
                    exceeded,
                    work: candidate,
                });
            }
            preflight = candidate;
            specs.push(ProcedureSpec {
                id,
                body: shape.body,
                callable: frame.node,
                empty_body: shape.empty_body,
                locator,
                lexical_parent: frame.lexical_parent,
                kind: shape.kind,
                properties: shape.properties,
            });
            let callable_path = push_declaration_path(&mut declaration_paths, child_path, segment);
            if shape.body.id() == frame.node.id() {
                if shape.attach_lexical_parent {
                    self_callable_scope = Some((id, callable_path));
                } else {
                    self_synthetic_scope = Some(SyntheticBodyScope {
                        procedure: id,
                        callable_path,
                    });
                }
            } else {
                callable_body_scope = Some((
                    shape.body.id(),
                    id,
                    callable_path,
                    shape.attach_lexical_parent,
                ));
            }
        }

        let children = named_children(frame.node);
        for child in children.into_iter().rev() {
            let inherited_synthetic = self_synthetic_scope.or(frame.synthetic_body_scope);
            let (lexical_parent, declaration_path, member_context, singleton_context, synthetic) =
                if let Some((_, procedure, path, attach)) =
                    callable_body_scope.filter(|(body_id, _, _, _)| *body_id == child.id())
                {
                    if attach {
                        (Some(procedure), path, false, false, None)
                    } else {
                        (
                            frame.lexical_parent,
                            child_path,
                            child_member_context,
                            child_singleton_context,
                            Some(SyntheticBodyScope {
                                procedure,
                                callable_path: path,
                            }),
                        )
                    }
                } else if let Some(synthetic) = inherited_synthetic {
                    if is_initializer_member_declaration(child) {
                        (
                            frame.lexical_parent,
                            child_path,
                            child_member_context,
                            child_singleton_context,
                            None,
                        )
                    } else {
                        (
                            Some(synthetic.procedure),
                            synthetic.callable_path,
                            false,
                            false,
                            Some(synthetic),
                        )
                    }
                } else if let Some((procedure, path)) = self_callable_scope {
                    (Some(procedure), path, false, false, None)
                } else {
                    (
                        frame.lexical_parent,
                        child_path,
                        child_member_context,
                        child_singleton_context,
                        None,
                    )
                };
            stack.push(ProcedureEnumerationFrame {
                node: child,
                lexical_parent,
                declaration_path,
                member_context,
                singleton_context,
                synthetic_body_scope: synthetic,
            });
        }
    }

    Ok(ProcedureEnumeration::Complete(specs))
}

struct CallableShape<'tree> {
    kind: ProcedureKind,
    segment_kind: DeclarationSegmentKind,
    body: Node<'tree>,
    empty_body: bool,
    properties: ProcedureProperties,
    attach_lexical_parent: bool,
}

fn callable_shape<'tree>(
    source: &str,
    node: Node<'tree>,
    singleton_context: bool,
) -> Option<CallableShape<'tree>> {
    let immediate = ProcedureInvocationKind::Immediate;
    let (kind, segment_kind, body, empty_body, is_static, synthetic, attach) = match node.kind() {
        "program" => (
            ProcedureKind::Initializer,
            DeclarationSegmentKind::Initializer,
            node,
            node.named_child_count() == 0,
            true,
            true,
            false,
        ),
        "class" | "module" | "singleton_class" => {
            let body = node.child_by_field_name("body").unwrap_or(node);
            (
                ProcedureKind::Initializer,
                DeclarationSegmentKind::Initializer,
                body,
                node.child_by_field_name("body").is_none(),
                true,
                true,
                false,
            )
        }
        "method" | "singleton_method" => {
            let name = node
                .child_by_field_name("name")
                .and_then(|name| node_text(source, name));
            let constructor =
                node.kind() == "method" && !singleton_context && name == Some("initialize");
            let kind = if constructor {
                ProcedureKind::Constructor
            } else {
                ProcedureKind::Method
            };
            let segment = if constructor {
                DeclarationSegmentKind::Constructor
            } else {
                DeclarationSegmentKind::Method
            };
            let body = node.child_by_field_name("body").unwrap_or(node);
            (
                kind,
                segment,
                body,
                node.child_by_field_name("body").is_none(),
                node.kind() == "singleton_method" || singleton_context,
                false,
                true,
            )
        }
        "lambda" => {
            let wrapper = node.child_by_field_name("body")?;
            (
                ProcedureKind::Lambda,
                DeclarationSegmentKind::Lambda,
                wrapper,
                wrapper.child_by_field_name("body").is_none(),
                false,
                false,
                true,
            )
        }
        "block" | "do_block" if node.parent().is_none_or(|parent| parent.kind() != "lambda") => {
            let body = node.child_by_field_name("body").unwrap_or(node);
            (
                ProcedureKind::Closure,
                DeclarationSegmentKind::Closure,
                body,
                node.child_by_field_name("body").is_none(),
                false,
                false,
                true,
            )
        }
        _ => return None,
    };
    Some(CallableShape {
        kind,
        segment_kind,
        body,
        empty_body,
        properties: ProcedureProperties {
            is_async: false,
            is_generator: false,
            is_static,
            is_synthetic: synthetic,
            invocation: immediate,
            ..ProcedureProperties::default()
        },
        attach_lexical_parent: attach,
    })
}

fn declaration_container_kind(node: Node<'_>) -> Option<DeclarationSegmentKind> {
    match node.kind() {
        "class" | "singleton_class" => Some(DeclarationSegmentKind::Type),
        "module" => Some(DeclarationSegmentKind::Namespace),
        _ => None,
    }
}

fn declaration_container_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    if node.kind() == "singleton_class" {
        return Some("<singleton-class>".into());
    }
    node.child_by_field_name("name")
        .and_then(|name| node_text(source, name))
        .filter(|name| !name.is_empty())
        .map(Box::<str>::from)
}

fn callable_name(source: &str, node: Node<'_>, kind: ProcedureKind) -> Option<Box<str>> {
    match node.kind() {
        "program" => Some("<file>".into()),
        "class" | "module" => declaration_container_name(source, node),
        "singleton_class" => Some("<singleton-class>".into()),
        "method" | "singleton_method" => node
            .child_by_field_name("name")
            .and_then(|name| node_text(source, name))
            .filter(|name| !name.is_empty())
            .map(Box::<str>::from),
        "lambda" => assigned_callable_name(source, node),
        "block" | "do_block" if kind == ProcedureKind::Closure => None,
        _ => None,
    }
}

fn assigned_callable_name(source: &str, mut node: Node<'_>) -> Option<Box<str>> {
    loop {
        let parent = node.parent()?;
        match parent.kind() {
            "parenthesized_statements" => node = parent,
            "assignment" if parent.child_by_field_name("right") == Some(node) => {
                return parent
                    .child_by_field_name("left")
                    .and_then(|left| node_text(source, left))
                    .filter(|name| !name.is_empty())
                    .map(Box::<str>::from);
            }
            _ => return None,
        }
    }
}

fn is_initializer_member_declaration(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "method" | "singleton_method" | "class" | "module" | "singleton_class"
    )
}

type RubyLoweringError = ProcedureLoweringError;

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

#[derive(Debug, Clone, Copy)]
struct CleanupRegion<'tree> {
    id: CleanupRegionId,
    body: Node<'tree>,
    outer_scope: ScopeFrameId,
}

#[derive(Debug, Clone)]
struct RubyControlFrame {
    break_label: Option<Box<str>>,
    next_label: Option<Box<str>>,
    redo_label: Option<Box<str>>,
    retry_label: Option<Box<str>>,
    callable_exit: bool,
}

struct LoweringContext<'tree, 'targets> {
    source: &'tree str,
    session: ProcedureLoweringSession<'targets>,
    procedure_kind: ProcedureKind,
    procedure_body_node_id: usize,
    procedure_runtime_body_node_id: usize,
    reuse_first_statement_entry: bool,
    nonlocal_cleanup_label: Option<Box<str>>,
    next_control_label: usize,
    cleanups: Vec<CleanupRegion<'tree>>,
    controls: HashMap<ScopeFrameId, Box<[RubyControlFrame]>>,
    local_bindings: &'targets LocalBindingTimeline,
}

fn lower_procedure<'tree, 'request>(
    prepared: &'tree PreparedSyntaxTree,
    spec: &ProcedureSpec<'tree>,
    local_bindings: &'request LocalBindingTimeline,
    has_parameter_defaults: bool,
    budget: &SemanticBudget,
    cancellation: &'request CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), RubyLoweringError> {
    let mut parts = ProcedureSemanticsParts::new(
        spec.id,
        spec.locator.clone(),
        spec.kind,
        SourceMappingId::new(0),
        EvidenceId::new(0),
    );
    parts.lexical_parent = spec.lexical_parent;
    parts.properties = spec.properties;
    let ProcedureLoweringStart {
        mut builder,
        session,
        entry,
        normal_exit,
        exceptional_exit,
        function_scope,
    } = ProcedureLoweringSession::start(parts, budget, cancellation)?;
    let runtime_body = if matches!(spec.body.kind(), "block" | "do_block") {
        spec.body.child_by_field_name("body").unwrap_or(spec.body)
    } else {
        spec.body
    };
    let mut context = LoweringContext {
        source: prepared.source(),
        session,
        procedure_kind: spec.kind,
        procedure_body_node_id: spec.body.id(),
        procedure_runtime_body_node_id: runtime_body.id(),
        reuse_first_statement_entry: matches!(
            spec.kind,
            ProcedureKind::Lambda | ProcedureKind::Closure
        ),
        nonlocal_cleanup_label: None,
        next_control_label: 0,
        cleanups: Vec::new(),
        controls: HashMap::default(),
        local_bindings,
    };
    context.controls.insert(function_scope, Box::new([]));

    if has_parameter_defaults {
        for (capability, detail) in [
            (
                SemanticCapability::Calls,
                "Ruby default parameter expressions may call code before the callable body and are not lowered",
            ),
            (
                SemanticCapability::Values,
                "Ruby omitted-argument selection and default-value binding are not represented",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                "Ruby default parameter evaluation may raise before the callable body",
            ),
        ] {
            context.add_gap(
                &mut builder,
                entry,
                SemanticGapSubject::Point,
                capability,
                SemanticGapKind::Unknown,
                detail,
            )?;
        }
    }
    if spec.kind == ProcedureKind::Closure {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::CallableReferences,
            SemanticGapKind::Unknown,
            "ordinary Ruby block capture and dynamic yielding target are not bound",
        )?;
    }
    if spec.kind == ProcedureKind::Constructor {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "Class#new allocation and initialize dispatch are not collapsed into a synthetic constructor call",
        )?;
    }
    if spec.kind == ProcedureKind::Initializer && spec.callable.kind() != "program" {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "Ruby class or module body execution is materialized separately from its non-call declaration site",
        )?;
    }

    let mut body_parent_scope = function_scope;
    if matches!(
        spec.kind,
        ProcedureKind::Closure | ProcedureKind::Initializer
    ) {
        let boundary = context.point(&mut builder, spec.body, Vec::new())?;
        let label = context.next_label("unknown-nonlocal-boundary");
        let nonlocal_scope = builder.push_scope(
            Some(function_scope),
            ScopeBinding::Loop {
                label: Some(label.clone()),
                break_target: boundary,
                break_edge_kind: ControlEdgeKind::Normal,
                continue_target: boundary,
                continue_edge_kind: ControlEdgeKind::Normal,
            },
        );
        context.copy_controls(function_scope, nonlocal_scope);
        context.nonlocal_cleanup_label = Some(label);
        body_parent_scope = nonlocal_scope;
    }

    let body_entry = if context.reuse_first_statement_entry {
        if let Some(first) = runtime_statement_children(runtime_body).first().copied() {
            context.statement_point(&mut builder, first)?
        } else {
            context.point(&mut builder, spec.body, Vec::new())?
        }
    } else {
        context.point(&mut builder, spec.body, Vec::new())?
    };
    let mut body_scope = body_parent_scope;
    if matches!(spec.kind, ProcedureKind::Lambda | ProcedureKind::Closure) {
        let exit_label = context.next_label("callable-exit");
        let exit_scope = builder.push_scope(
            Some(body_parent_scope),
            ScopeBinding::Loop {
                label: Some(exit_label.clone()),
                break_target: normal_exit,
                break_edge_kind: ControlEdgeKind::Normal,
                continue_target: normal_exit,
                continue_edge_kind: ControlEdgeKind::Normal,
            },
        );
        context.copy_controls(body_parent_scope, exit_scope);
        let redo_label = context.next_label("callable-redo");
        let redo_scope = builder.push_scope(
            Some(exit_scope),
            ScopeBinding::Loop {
                label: Some(redo_label.clone()),
                break_target: normal_exit,
                break_edge_kind: ControlEdgeKind::Normal,
                continue_target: body_entry,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        context.extend_controls(
            exit_scope,
            redo_scope,
            RubyControlFrame {
                break_label: (spec.kind == ProcedureKind::Lambda).then_some(exit_label.clone()),
                next_label: Some(exit_label),
                redo_label: Some(redo_label),
                retry_label: None,
                callable_exit: true,
            },
        );
        body_scope = redo_scope;
    }

    let body_next = if spec.kind == ProcedureKind::Initializer {
        EdgeTarget::normal(normal_exit)
    } else {
        let implicit_return = context.point(&mut builder, spec.body, Vec::new())?;
        let value = context.value(&mut builder, implicit_return, SemanticValueKind::Return)?;
        context.append_effect(
            &mut builder,
            implicit_return,
            SemanticEffect::ProcedureReturn { value: Some(value) },
        )?;
        context.edge(
            &mut builder,
            implicit_return,
            EdgeTarget::normal(normal_exit),
        )?;
        EdgeTarget::normal(implicit_return)
    };
    context.edge(&mut builder, entry, EdgeTarget::normal(body_entry))?;

    let initial = if spec.empty_body {
        context.edge(&mut builder, body_entry, body_next)?;
        None
    } else {
        Some(Work::Statement {
            node: spec.body,
            entry: body_entry,
            next: body_next,
            scope: body_scope,
        })
    };
    let mut drive_error = None;
    if let Some(initial) = initial
        && let Err(error) =
            builder.drive_iteratively(initial, cancellation, |builder, work, stack| {
                context.step(builder, work, stack)
            })
    {
        drive_error = Some(error);
    }
    if let Some(error) = drive_error {
        let work = builder.prospective_work();
        return match error {
            DriveError::Cancelled | DriveError::Step(RubyLoweringError::Cancelled(_)) => {
                Err(RubyLoweringError::Cancelled(Box::new(work)))
            }
            DriveError::ExceededBudget(exceeded) => {
                Err(RubyLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(RubyLoweringError::Budget(exceeded, _)) => {
                Err(RubyLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(RubyLoweringError::Invalid(detail)) => {
                Err(RubyLoweringError::Invalid(detail))
            }
        };
    }

    if builder
        .seal_unreachable_regions(entry, normal_exit, exceptional_exit, cancellation)
        .is_err()
    {
        return Err(RubyLoweringError::Cancelled(Box::new(
            builder.prospective_work(),
        )));
    }
    let work_before_freeze = builder.prospective_work();
    builder
        .finish_with_work()
        .map_err(|error| RubyLoweringError::Budget(error, Box::new(work_before_freeze)))
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    fn step(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        work: Work<'tree>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        if self.session.cancellation().is_cancelled() {
            return Err(RubyLoweringError::Cancelled(Box::default()));
        }
        match work {
            Work::Statement {
                node,
                entry,
                next,
                scope,
            } => self.statement(builder, node, entry, next, scope, stack),
            Work::Expression {
                node,
                entry,
                next,
                scope,
            } => self.expression(builder, node, entry, next, scope, stack),
            Work::Condition {
                node,
                entry,
                when_true,
                when_false,
                scope,
            } => self.condition(builder, node, entry, when_true, when_false, scope, stack),
        }
    }

    fn next_label(&mut self, role: &str) -> Box<str> {
        let label = format!("<ruby-{role}-{}>", self.next_control_label).into_boxed_str();
        self.next_control_label += 1;
        label
    }

    fn copy_controls(&mut self, parent: ScopeFrameId, child: ScopeFrameId) {
        let controls = self.controls.get(&parent).cloned().unwrap_or_default();
        self.controls.insert(child, controls);
    }

    fn extend_controls(
        &mut self,
        parent: ScopeFrameId,
        child: ScopeFrameId,
        frame: RubyControlFrame,
    ) {
        let mut controls = self
            .controls
            .get(&parent)
            .map(|controls| controls.to_vec())
            .unwrap_or_default();
        controls.push(frame);
        self.controls.insert(child, controls.into_boxed_slice());
    }

    #[allow(clippy::too_many_arguments)]
    fn statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        match node.kind() {
            "program"
            | "block_body"
            | "do"
            | "then"
            | "else"
            | "ensure"
            | "parenthesized_statements" => {
                let children = runtime_statement_children(node);
                if self.reuse_first_statement_entry
                    && node.id() == self.procedure_runtime_body_node_id
                {
                    self.schedule_statements_reusing_entry(
                        builder, entry, &children, next, scope, stack,
                    )
                } else {
                    self.schedule_statements(builder, entry, &children, next, scope, stack)
                }
            }
            "body_statement" if body_has_rescue_or_ensure(node) => {
                self.try_body(builder, node, entry, next, scope, stack)
            }
            "body_statement" => {
                let children = ordinary_body_statements(node);
                if self.reuse_first_statement_entry
                    && node.id() == self.procedure_runtime_body_node_id
                {
                    self.schedule_statements_reusing_entry(
                        builder, entry, &children, next, scope, stack,
                    )
                } else {
                    self.schedule_statements(builder, entry, &children, next, scope, stack)
                }
            }
            "block" | "do_block" if node.id() == self.procedure_body_node_id => {
                if let Some(body) = node.child_by_field_name("body") {
                    stack.push(Work::Statement {
                        node: body,
                        entry,
                        next,
                        scope,
                    });
                    Ok(())
                } else {
                    self.edge(builder, entry, next)
                }
            }
            "begin" => self.try_body(builder, node, entry, next, scope, stack),
            "if" | "unless" | "elsif" | "if_modifier" | "unless_modifier" | "conditional" => {
                self.if_expression(builder, node, entry, next, scope, stack)
            }
            "while" | "until" | "while_modifier" | "until_modifier" => {
                self.loop_expression(builder, node, entry, next, scope, stack)
            }
            "for" => self.for_expression(builder, node, entry, next, scope, stack),
            "case" | "case_match" => self.case_expression(builder, node, entry, next, scope, stack),
            "rescue_modifier" => self.rescue_modifier(builder, node, entry, next, scope, stack),
            "return" => self.return_expression(builder, node, entry, scope, stack),
            "break" | "next" | "redo" | "retry" => {
                self.control_expression(builder, node, entry, scope, stack)
            }
            "call" => self.call_expression(builder, node, entry, next, scope, stack),
            "yield" => self.yield_expression(builder, node, entry, next, scope, stack),
            "method" | "singleton_method" | "lambda" | "block" | "do_block" => {
                self.callable_value(builder, node, entry, next)
            }
            "class" | "module" | "singleton_class" => {
                self.type_declaration(builder, node, entry, next, scope, stack)
            }
            "begin_block" | "end_block" => {
                self.deferred_lifecycle_block(builder, node, entry, next)
            }
            "alias" | "undef" => self.callable_table_mutation(builder, node, entry, next),
            _ => self.expression(builder, node, entry, next, scope, stack),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        match node.kind() {
            "program"
            | "body_statement"
            | "block_body"
            | "do"
            | "then"
            | "else"
            | "ensure"
            | "parenthesized_statements"
            | "begin"
            | "if"
            | "unless"
            | "elsif"
            | "if_modifier"
            | "unless_modifier"
            | "while"
            | "until"
            | "while_modifier"
            | "until_modifier"
            | "for"
            | "case"
            | "case_match"
            | "rescue_modifier"
            | "return"
            | "break"
            | "next"
            | "redo"
            | "retry"
            | "yield"
            | "class"
            | "module"
            | "singleton_class"
            | "begin_block"
            | "end_block" => self.statement(builder, node, entry, next, scope, stack),
            "block" | "do_block" if node.id() == self.procedure_body_node_id => {
                self.statement(builder, node, entry, next, scope, stack)
            }
            "call" => self.call_expression(builder, node, entry, next, scope, stack),
            "conditional" => self.if_expression(builder, node, entry, next, scope, stack),
            "binary" if is_short_circuit_binary(self.source, node) => {
                self.boolean_value(builder, node, entry, next, scope, stack)
            }
            "binary" | "unary" => self.implicit_operator(builder, node, entry, next, scope, stack),
            "assignment" | "operator_assignment" => {
                self.assignment(builder, node, entry, next, scope, stack)
            }
            "element_reference" => self.element_reference(builder, node, entry, next, scope, stack),
            "identifier" => self.ambiguous_identifier(builder, node, entry, next, scope, stack),
            "method" | "singleton_method" | "lambda" | "block" | "do_block" => {
                self.callable_value(builder, node, entry, next)
            }
            "super" => self.unsupported_super(builder, node, entry, next, scope, stack),
            _ if is_runtime_leaf(node.kind()) => self.edge(builder, entry, next),
            _ => {
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn condition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        if node.kind() == "binary" {
            let operator = node
                .child_by_field_name("operator")
                .and_then(|operator| node_text(self.source, operator));
            if matches!(operator, Some("&&" | "and")) {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                stack.push(Work::Condition {
                    node: right,
                    entry: right_entry,
                    when_true,
                    when_false,
                    scope,
                });
                stack.push(Work::Condition {
                    node: left,
                    entry,
                    when_true: EdgeTarget {
                        point: right_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false,
                    scope,
                });
                return Ok(());
            }
            if matches!(operator, Some("||" | "or")) {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                stack.push(Work::Condition {
                    node: right,
                    entry: right_entry,
                    when_true,
                    when_false,
                    scope,
                });
                stack.push(Work::Condition {
                    node: left,
                    entry,
                    when_true,
                    when_false: EdgeTarget {
                        point: right_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope,
                });
                return Ok(());
            }
        }
        if node.kind() == "unary"
            && node
                .child_by_field_name("operator")
                .and_then(|operator| node_text(self.source, operator))
                .is_some_and(|operator| matches!(operator, "!" | "not"))
        {
            let operand = required_field(node, "operand")?;
            let decision = self.point(builder, node, Vec::new())?;
            self.negation_gaps(builder, decision)?;
            self.edge(builder, decision, when_true)?;
            self.edge(builder, decision, when_false)?;
            stack.push(Work::Expression {
                node: operand,
                entry,
                next: EdgeTarget::normal(decision),
                scope,
            });
            return Ok(());
        }

        let decision = self.point(builder, node, Vec::new())?;
        self.edge(builder, decision, when_true)?;
        self.edge(builder, decision, when_false)?;
        stack.push(Work::Expression {
            node,
            entry,
            next: EdgeTarget::normal(decision),
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn if_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let condition = required_field(node, "condition")?;
        let consequence = node
            .child_by_field_name("consequence")
            .or_else(|| node.child_by_field_name("body"));
        let alternative = node.child_by_field_name("alternative");
        let consequence_nodes = consequence.map(branch_statements).unwrap_or_default();
        let alternative_nodes = alternative.map(branch_statements).unwrap_or_default();
        let consequence_entry =
            self.prepare_statements(builder, &consequence_nodes, next, scope, stack)?;
        let alternative_entry =
            self.prepare_statements(builder, &alternative_nodes, next, scope, stack)?;
        let consequence_target = consequence_entry.map(EdgeTarget::normal).unwrap_or(next);
        let alternative_target = alternative_entry.map(EdgeTarget::normal).unwrap_or(next);
        let inverted = matches!(node.kind(), "unless" | "unless_modifier");
        let condition_entry = self.point(builder, condition, Vec::new())?;
        self.edge(builder, entry, EdgeTarget::normal(condition_entry))?;
        stack.push(Work::Condition {
            node: condition,
            entry: condition_entry,
            when_true: if inverted {
                EdgeTarget {
                    point: alternative_target.point,
                    kind: ControlEdgeKind::ConditionalTrue,
                }
            } else {
                EdgeTarget {
                    point: consequence_target.point,
                    kind: ControlEdgeKind::ConditionalTrue,
                }
            },
            when_false: if inverted {
                EdgeTarget {
                    point: consequence_target.point,
                    kind: ControlEdgeKind::ConditionalFalse,
                }
            } else {
                EdgeTarget {
                    point: alternative_target.point,
                    kind: ControlEdgeKind::ConditionalFalse,
                }
            },
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn loop_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let condition = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let condition_entry = self.point(builder, condition, Vec::new())?;
        let body_children = runtime_statement_children(body);
        let body_entry = if let (Some(first), Some(last)) = (
            body_children.first().copied(),
            body_children.last().copied(),
        ) {
            self.point_through(builder, first, last, Vec::new())?
        } else {
            self.point(builder, body, Vec::new())?
        };
        let body_scope = self.push_loop_scopes(builder, scope, next, condition_entry, body_entry);
        let inverted = matches!(node.kind(), "until" | "until_modifier");
        let body_target = EdgeTarget {
            point: body_entry,
            kind: if inverted {
                ControlEdgeKind::ConditionalFalse
            } else {
                ControlEdgeKind::ConditionalTrue
            },
        };
        let exit_target = EdgeTarget {
            point: next.point,
            kind: if inverted {
                ControlEdgeKind::ConditionalTrue
            } else {
                ControlEdgeKind::ConditionalFalse
            },
        };

        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: condition_entry,
                kind: ControlEdgeKind::LoopBack,
            },
            scope: body_scope,
        });
        stack.push(Work::Condition {
            node: condition,
            entry: condition_entry,
            when_true: if inverted { exit_target } else { body_target },
            when_false: if inverted { body_target } else { exit_target },
            scope,
        });

        let post_test =
            matches!(node.kind(), "while_modifier" | "until_modifier") && body.kind() == "begin";
        if post_test {
            self.edge(builder, entry, EdgeTarget::normal(body_entry))
        } else {
            self.edge(builder, entry, EdgeTarget::normal(condition_entry))
        }
    }

    fn push_loop_scopes(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        parent: ScopeFrameId,
        break_target: EdgeTarget,
        next_target: ProgramPointId,
        redo_target: ProgramPointId,
    ) -> ScopeFrameId {
        let outer_label = self.next_label("loop-next");
        let outer = builder.push_scope(
            Some(parent),
            ScopeBinding::Loop {
                label: Some(outer_label.clone()),
                break_target: break_target.point,
                break_edge_kind: break_target.kind,
                continue_target: next_target,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        self.copy_controls(parent, outer);
        let redo_label = self.next_label("loop-redo");
        let inner = builder.push_scope(
            Some(outer),
            ScopeBinding::Loop {
                label: Some(redo_label.clone()),
                break_target: break_target.point,
                break_edge_kind: break_target.kind,
                continue_target: redo_target,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        self.extend_controls(
            outer,
            inner,
            RubyControlFrame {
                break_label: Some(outer_label.clone()),
                next_label: Some(outer_label),
                redo_label: Some(redo_label),
                retry_label: None,
                callable_exit: false,
            },
        );
        inner
    }

    #[allow(clippy::too_many_arguments)]
    fn for_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let value_wrapper = required_field(node, "value")?;
        let iterable = first_runtime_named_child(value_wrapper).ok_or_else(|| {
            RubyLoweringError::Invalid("Ruby for-in wrapper has no iterable expression".into())
        })?;
        let body = required_field(node, "body")?;
        let decision = self.point(builder, value_wrapper, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        for (capability, kind, detail) in [
            (
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "Ruby for iteration protocol calls are not emitted as synthetic call sites",
            ),
            (
                SemanticCapability::Values,
                SemanticGapKind::Unknown,
                "per-iteration destructuring and loop-variable binding require value refinement",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "iteration protocol lookup and execution may raise",
            ),
        ] {
            self.add_gap(
                builder,
                decision,
                SemanticGapSubject::Point,
                capability,
                kind,
                detail,
            )?;
        }
        self.edge(
            builder,
            decision,
            EdgeTarget {
                point: body_entry,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        self.edge(
            builder,
            decision,
            EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        let body_scope = self.push_loop_scopes(builder, scope, next, decision, body_entry);
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: decision,
                kind: ControlEdgeKind::LoopBack,
            },
            scope: body_scope,
        });
        stack.push(Work::Expression {
            node: iterable,
            entry,
            next: EdgeTarget::normal(decision),
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn case_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let clauses = named_children(node)
            .into_iter()
            .filter(|child| matches!(child.kind(), "when" | "in_clause"))
            .collect::<Vec<_>>();
        let has_case_value = node.child_by_field_name("value").is_some();
        let alternative = node.child_by_field_name("else").or_else(|| {
            named_children(node)
                .into_iter()
                .find(|child| child.kind() == "else")
        });
        let mut tests = Vec::with_capacity(clauses.len());
        for clause in &clauses {
            if clause.kind() == "when" {
                let mut clause_tests = Vec::new();
                for pattern in children_by_field_name(*clause, "pattern") {
                    clause_tests.push((
                        Some(pattern),
                        self.point(builder, pattern, Vec::new())?,
                        self.point(builder, pattern, Vec::new())?,
                    ));
                }
                if clause_tests.is_empty() {
                    return Err(RubyLoweringError::Invalid(format!(
                        "when clause at bytes {}..{} has no structured pattern",
                        clause.start_byte(),
                        clause.end_byte()
                    )));
                }
                tests.push(clause_tests);
            } else {
                let decision = self.point(builder, *clause, Vec::new())?;
                tests.push(vec![(None, decision, decision)]);
            }
        }
        let body_entries = clauses
            .iter()
            .map(|clause| self.point(builder, *clause, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let alternative_entry = alternative
            .map(|body| self.point(builder, body, Vec::new()))
            .transpose()?;

        let unmatched = if let Some(alternative_entry) = alternative_entry {
            EdgeTarget::normal(alternative_entry)
        } else if node.kind() == "case_match" {
            let point = self.point(builder, node, Vec::new())?;
            let value = self.value(builder, point, SemanticValueKind::Exception)?;
            self.append_effect(builder, point, SemanticEffect::Throw { value: Some(value) })?;
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "unmatched Ruby pattern case raises NoMatchingPatternError",
            )?;
            self.abrupt(builder, point, scope, CompletionKind::Throw, None, stack)?;
            EdgeTarget {
                point,
                kind: ControlEdgeKind::Exceptional,
            }
        } else {
            next
        };

        if let (Some(alternative), Some(alternative_entry)) = (alternative, alternative_entry) {
            stack.push(Work::Statement {
                node: alternative,
                entry: alternative_entry,
                next,
                scope,
            });
        }
        for index in (0..clauses.len()).rev() {
            let clause = clauses[index];
            let clause_no_match = tests
                .get(index + 1)
                .and_then(|tests| tests.first())
                .map(|(_, entry, _)| EdgeTarget {
                    point: *entry,
                    kind: ControlEdgeKind::Normal,
                })
                .unwrap_or(unmatched);
            let body = clause.child_by_field_name("body");
            if let Some(body) = body {
                stack.push(Work::Statement {
                    node: body,
                    entry: body_entries[index],
                    next,
                    scope,
                });
            } else {
                self.edge(builder, body_entries[index], next)?;
            }

            let guard = clause.child_by_field_name("guard");
            let guard_entry = guard
                .map(|guard| self.point(builder, guard, Vec::new()))
                .transpose()?;
            for test_index in (0..tests[index].len()).rev() {
                let (pattern, test_entry, decision) = tests[index][test_index];
                let no_match = tests[index]
                    .get(test_index + 1)
                    .map(|(_, entry, _)| EdgeTarget::normal(*entry))
                    .unwrap_or(clause_no_match);
                let implicit_matching = clause.kind() == "in_clause" || has_case_value;
                if implicit_matching {
                    self.add_gap(
                        builder,
                        decision,
                        SemanticGapSubject::Point,
                        SemanticCapability::Calls,
                        SemanticGapKind::Unsupported,
                        if clause.kind() == "when" {
                            "Ruby case matching invokes pattern === methods that are not emitted synthetically"
                        } else {
                            "Ruby pattern deconstruction invokes implicit protocol methods that are not emitted synthetically"
                        },
                    )?;
                    self.add_gap(
                        builder,
                        decision,
                        SemanticGapSubject::Point,
                        SemanticCapability::ExceptionalControlFlow,
                        SemanticGapKind::Unknown,
                        "Ruby implicit case matching may raise",
                    )?;
                }
                self.add_gap(
                    builder,
                    decision,
                    SemanticGapSubject::Point,
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    if implicit_matching {
                        "case pattern compatibility and bindings require runtime value refinement"
                    } else {
                        "case predicate truthiness requires runtime value refinement"
                    },
                )?;

                if let (Some(guard), Some(guard_entry)) = (guard, guard_entry) {
                    let guard_condition = guard.child_by_field_name("condition").unwrap_or(guard);
                    self.edge(
                        builder,
                        decision,
                        EdgeTarget {
                            point: guard_entry,
                            kind: ControlEdgeKind::SwitchCase,
                        },
                    )?;
                    self.edge(builder, decision, no_match)?;
                    let unless = guard.kind() == "unless_guard";
                    stack.push(Work::Condition {
                        node: guard_condition,
                        entry: guard_entry,
                        when_true: if unless {
                            no_match
                        } else {
                            EdgeTarget::normal(body_entries[index])
                        },
                        when_false: if unless {
                            EdgeTarget::normal(body_entries[index])
                        } else {
                            no_match
                        },
                        scope,
                    });
                } else {
                    self.edge(
                        builder,
                        decision,
                        EdgeTarget {
                            point: body_entries[index],
                            kind: ControlEdgeKind::SwitchCase,
                        },
                    )?;
                    self.edge(builder, decision, no_match)?;
                }
                if let Some(pattern) = pattern {
                    stack.push(Work::Expression {
                        node: pattern,
                        entry: test_entry,
                        next: EdgeTarget::normal(decision),
                        scope,
                    });
                }
            }
        }

        let first = tests
            .first()
            .and_then(|tests| tests.first())
            .map(|(_, entry, _)| EdgeTarget::normal(*entry))
            .unwrap_or(unmatched);
        if let Some(value) = node.child_by_field_name("value") {
            stack.push(Work::Expression {
                node: value,
                entry,
                next: first,
                scope,
            });
        } else {
            self.edge(builder, entry, first)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn try_body(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let parts = body_components(node);
        if parts.rescues.is_empty() && parts.ensure.is_none() {
            let mut statements = parts.protected;
            if let Some(alternative) = parts.alternative {
                statements.push(alternative);
            }
            return self.schedule_statements(builder, entry, &statements, next, scope, stack);
        }

        let (cleanup_scope, cleanup_region) = if let Some(finalizer) = parts.ensure {
            let region = CleanupRegionId::new(
                u32::try_from(self.cleanups.len())
                    .map_err(|_| RubyLoweringError::Invalid("too many cleanup regions".into()))?,
            );
            self.cleanups.push(CleanupRegion {
                id: region,
                body: finalizer,
                outer_scope: scope,
            });
            let cleanup_scope = builder.push_scope(Some(scope), ScopeBinding::Cleanup { region });
            self.copy_controls(scope, cleanup_scope);
            (cleanup_scope, Some(region))
        } else {
            (scope, None)
        };

        let normal_destination = if cleanup_region.is_some() && next.kind != ControlEdgeKind::Normal
        {
            let relay = self.point(builder, node, Vec::new())?;
            self.edge(builder, relay, next)?;
            relay
        } else {
            next.point
        };
        let normal_route = cleanup_region
            .map(|region| builder.normal_cleanup_completion(region, normal_destination));

        let protected_can_complete = parts
            .protected
            .last()
            .is_none_or(|statement| !statement_definitely_abrupt(*statement));
        let after_protected = if let Some(alternative) = parts.alternative {
            let alternative_entry = self.point(builder, alternative, Vec::new())?;
            if let Some(route) = &normal_route {
                let alternative_exit = self.point(builder, alternative, Vec::new())?;
                self.route(builder, alternative_exit, route, stack)?;
                stack.push(Work::Statement {
                    node: alternative,
                    entry: alternative_entry,
                    next: EdgeTarget::normal(alternative_exit),
                    scope: cleanup_scope,
                });
            } else {
                stack.push(Work::Statement {
                    node: alternative,
                    entry: alternative_entry,
                    next,
                    scope: cleanup_scope,
                });
            }
            EdgeTarget::normal(alternative_entry)
        } else if let Some(route) = normal_route.as_ref().filter(|_| protected_can_complete) {
            self.route_target(builder, route, stack)?
        } else {
            next
        };

        let protected_scope = if parts.rescues.is_empty() {
            cleanup_scope
        } else {
            let dispatcher = self.point(builder, node, Vec::new())?;
            self.add_gap(
                builder,
                dispatcher,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "Ruby rescue exception-list evaluation, class matching, and binding require runtime refinement",
            )?;
            for rescue in &parts.rescues {
                let rescue_entry = self.point(builder, *rescue, Vec::new())?;
                self.edge(
                    builder,
                    dispatcher,
                    EdgeTarget {
                        point: rescue_entry,
                        kind: ControlEdgeKind::SwitchCase,
                    },
                )?;
                let retry_label = self.next_label("rescue-retry");
                let retry_scope = builder.push_scope(
                    Some(cleanup_scope),
                    ScopeBinding::Loop {
                        label: Some(retry_label.clone()),
                        break_target: next.point,
                        break_edge_kind: next.kind,
                        continue_target: entry,
                        continue_edge_kind: ControlEdgeKind::LoopBack,
                    },
                );
                self.extend_controls(
                    cleanup_scope,
                    retry_scope,
                    RubyControlFrame {
                        break_label: None,
                        next_label: None,
                        redo_label: None,
                        retry_label: Some(retry_label),
                        callable_exit: false,
                    },
                );
                if rescue.child_by_field_name("exceptions").is_some() {
                    self.add_gap(
                        builder,
                        rescue_entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::Calls,
                        SemanticGapKind::Unknown,
                        "rescue exception class expressions and splats may execute calls on the exceptional path",
                    )?;
                }
                if rescue.child_by_field_name("variable").is_some() {
                    self.add_gap(
                        builder,
                        rescue_entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::Values,
                        SemanticGapKind::Unknown,
                        "rescue exception variable binding is not represented",
                    )?;
                }
                let body = rescue.child_by_field_name("body");
                if let Some(body) = body {
                    if let Some(route) = &normal_route {
                        let rescue_exit = self.point(builder, body, Vec::new())?;
                        self.route(builder, rescue_exit, route, stack)?;
                        stack.push(Work::Statement {
                            node: body,
                            entry: rescue_entry,
                            next: EdgeTarget::normal(rescue_exit),
                            scope: retry_scope,
                        });
                    } else {
                        stack.push(Work::Statement {
                            node: body,
                            entry: rescue_entry,
                            next,
                            scope: retry_scope,
                        });
                    }
                } else if let Some(route) = &normal_route {
                    self.route(builder, rescue_entry, route, stack)?;
                } else {
                    self.edge(builder, rescue_entry, next)?;
                }
            }
            let unmatched = self.point(builder, node, Vec::new())?;
            self.edge(
                builder,
                dispatcher,
                EdgeTarget {
                    point: unmatched,
                    kind: ControlEdgeKind::Exceptional,
                },
            )?;
            self.abrupt(
                builder,
                unmatched,
                cleanup_scope,
                CompletionKind::Throw,
                None,
                stack,
            )?;
            let handler = builder.push_scope(
                Some(cleanup_scope),
                ScopeBinding::Handler { entry: dispatcher },
            );
            self.copy_controls(cleanup_scope, handler);
            handler
        };

        if parts.protected.is_empty() {
            self.edge(builder, entry, after_protected)?;
        } else {
            self.schedule_statements(
                builder,
                entry,
                &parts.protected,
                after_protected,
                protected_scope,
                stack,
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn rescue_modifier(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let body = required_field(node, "body")?;
        let handler = required_field(node, "handler")?;
        let dispatcher = self.point(builder, node, Vec::new())?;
        let handler_entry = self.point(builder, handler, Vec::new())?;
        self.add_gap(
            builder,
            dispatcher,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            "rescue modifier handles StandardError-compatible exceptions only",
        )?;
        self.edge(
            builder,
            dispatcher,
            EdgeTarget {
                point: handler_entry,
                kind: ControlEdgeKind::SwitchCase,
            },
        )?;
        let unmatched = self.point(builder, node, Vec::new())?;
        self.edge(
            builder,
            dispatcher,
            EdgeTarget {
                point: unmatched,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;
        self.abrupt(
            builder,
            unmatched,
            scope,
            CompletionKind::Throw,
            None,
            stack,
        )?;
        let body_scope =
            builder.push_scope(Some(scope), ScopeBinding::Handler { entry: dispatcher });
        self.copy_controls(scope, body_scope);
        stack.push(Work::Expression {
            node: handler,
            entry: handler_entry,
            next,
            scope,
        });
        stack.push(Work::Expression {
            node: body,
            entry,
            next,
            scope: body_scope,
        });
        Ok(())
    }

    fn return_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let terminal = if node.named_child_count() == 0 {
            entry
        } else {
            self.point(builder, node, Vec::new())?
        };
        if self.procedure_kind == ProcedureKind::Closure {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unsupported,
                "return from an ordinary Ruby block targets its defining method, not the block procedure",
            )?;
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "ordinary block return may raise LocalJumpError after its defining frame has exited",
            )?;
            let label = self.nonlocal_cleanup_label.clone().ok_or_else(|| {
                RubyLoweringError::Invalid(
                    "ordinary block return is missing its cleanup boundary".into(),
                )
            })?;
            self.abrupt(
                builder,
                terminal,
                scope,
                CompletionKind::Break,
                Some(&label),
                stack,
            )?;
        } else if self.procedure_kind == ProcedureKind::Initializer {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unsupported,
                "return from a Ruby file, class, or module body has no represented method target",
            )?;
            let label = self.nonlocal_cleanup_label.clone().ok_or_else(|| {
                RubyLoweringError::Invalid(
                    "initializer return is missing its cleanup boundary".into(),
                )
            })?;
            self.abrupt(
                builder,
                terminal,
                scope,
                CompletionKind::Break,
                Some(&label),
                stack,
            )?;
        } else {
            let value = self.value(builder, terminal, SemanticValueKind::Return)?;
            self.append_effect(
                builder,
                terminal,
                SemanticEffect::ProcedureReturn { value: Some(value) },
            )?;
            self.abrupt(
                builder,
                terminal,
                scope,
                CompletionKind::Return,
                None,
                stack,
            )?;
        }
        let arguments = node
            .named_child(0)
            .map(runtime_expression_children)
            .unwrap_or_default();
        if arguments.is_empty() {
            return Ok(());
        }
        self.schedule_expressions(
            builder,
            entry,
            &arguments,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    fn control_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let terminal = if node.named_child_count() == 0 {
            entry
        } else {
            self.point(builder, node, Vec::new())?
        };
        let control = self.controls.get(&scope).and_then(|frames| {
            frames.iter().rev().find_map(|frame| {
                let label = match node.kind() {
                    "break" => frame.break_label.as_deref(),
                    "next" => frame.next_label.as_deref(),
                    "redo" => frame.redo_label.as_deref(),
                    "retry" => frame.retry_label.as_deref(),
                    _ => None,
                }?;
                Some((label.to_owned(), frame.callable_exit))
            })
        });
        let kind = match node.kind() {
            "break" => CompletionKind::Break,
            "next" | "redo" | "retry" => CompletionKind::Continue,
            _ => unreachable!("control_expression only receives Ruby abrupt nodes"),
        };
        if let Some((label, callable_exit)) = control.as_ref() {
            if *callable_exit && matches!(node.kind(), "break" | "next") {
                let value = self.value(builder, terminal, SemanticValueKind::Return)?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::ProcedureReturn { value: Some(value) },
                )?;
            }
            self.abrupt(builder, terminal, scope, kind, Some(label), stack)?;
        } else {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unsupported,
                match node.kind() {
                    "break" => "block or invalid-context break target is not represented",
                    "next" => "invalid-context next target is not represented",
                    "redo" => "redo target is not proven in this callable context",
                    "retry" => "retry has no enclosing represented rescue target",
                    _ => unreachable!(),
                },
            )?;
            if matches!(node.kind(), "break" | "retry") {
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unknown,
                    "invalid or escaped Ruby non-local control may raise LocalJumpError",
                )?;
            }
            if self.procedure_kind == ProcedureKind::Closure && node.kind() == "break" {
                let label = self.nonlocal_cleanup_label.clone().ok_or_else(|| {
                    RubyLoweringError::Invalid(
                        "ordinary block break is missing its cleanup boundary".into(),
                    )
                })?;
                self.abrupt(
                    builder,
                    terminal,
                    scope,
                    CompletionKind::Break,
                    Some(&label),
                    stack,
                )?;
            }
        }
        let arguments = node
            .named_child(0)
            .map(runtime_expression_children)
            .unwrap_or_default();
        if arguments.is_empty() {
            return Ok(());
        }
        self.schedule_expressions(
            builder,
            entry,
            &arguments,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn call_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        if node
            .child_by_field_name("method")
            .is_some_and(|method| method.kind() == "super")
        {
            return self.unsupported_super(builder, node, entry, next, scope, stack);
        }
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let callee = self.value(builder, invoke, SemanticValueKind::Callable)?;
        let result = self.value(builder, invoke, SemanticValueKind::Temporary)?;
        let thrown = self.value(builder, invoke, SemanticValueKind::Exception)?;
        let receiver_node = node.child_by_field_name("receiver");
        let receiver = receiver_node
            .map(|_| self.value(builder, invoke, SemanticValueKind::Receiver))
            .transpose()?;
        let method = node
            .child_by_field_name("method")
            .and_then(|method| node_text(self.source, method));
        let receiver_text = receiver_node.and_then(|receiver| node_text(self.source, receiver));
        let callable_kind = if receiver.is_some() {
            CallableReferenceKind::BoundMethod
        } else {
            CallableReferenceKind::Function
        };
        let resolution = if matches!(method, Some("send" | "public_send")) {
            CallableTargetResolution::Unsupported
        } else {
            CallableTargetResolution::Unknown
        };
        let metadata = self.metadata(invoke)?;
        self.append_effect(
            builder,
            invoke,
            SemanticEffect::CallableReference {
                result: callee,
                callable: CallableValue {
                    kind: callable_kind,
                    targets: resolution.clone(),
                    target_evidence: metadata.evidence,
                    bound_receiver: receiver,
                    environment: None,
                },
            },
        )?;

        let argument_nodes = call_arguments(node);
        let attached_block = node.child_by_field_name("block");
        let argument_count = argument_nodes.len() + usize::from(attached_block.is_some());
        let arguments = (0..argument_count)
            .map(|_| self.value(builder, invoke, SemanticValueKind::Temporary))
            .collect::<Result<Vec<_>, _>>()?;
        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver,
                arguments: arguments.into_iter().map(Into::into).collect(),
                result: Some(result),
                thrown: Some(thrown),
                declared_targets: resolution.clone(),
                normal_continuation: normal,
                exceptional_continuation: exceptional,
            },
        )?;
        self.edge(builder, invoke, EdgeTarget::normal(normal))?;
        self.edge(
            builder,
            invoke,
            EdgeTarget {
                point: exceptional,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;
        self.edge(builder, normal, next)?;
        self.route_call_exceptional(builder, exceptional, next, scope, stack)?;
        self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;
        self.add_gap(
            builder,
            invoke,
            SemanticGapSubject::CallSite(call_site),
            SemanticCapability::DynamicDispatch,
            SemanticGapKind::Unknown,
            "Ruby method dispatch may select an override or method_missing target; complete receiver-class coverage requires runtime refinement",
        )?;
        self.ruby_call_gaps(
            builder,
            invoke,
            call_site,
            receiver_text,
            method,
            attached_block.is_some(),
        )?;

        let safe_navigation = node
            .child_by_field_name("operator")
            .and_then(|operator| node_text(self.source, operator))
            == Some("&.");
        if safe_navigation {
            let decision = self.point(builder, node, Vec::new())?;
            self.schedule_expressions_with_first_edge(
                builder,
                decision,
                &argument_nodes,
                EdgeTarget::normal(invoke),
                ControlEdgeKind::ConditionalTrue,
                scope,
                stack,
            )?;
            self.edge(
                builder,
                decision,
                EdgeTarget {
                    point: next.point,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
            )?;
            if let Some(receiver) = receiver_node {
                stack.push(Work::Expression {
                    node: receiver,
                    entry,
                    next: EdgeTarget::normal(decision),
                    scope,
                });
            } else {
                self.edge(builder, entry, EdgeTarget::normal(decision))?;
            }
            return Ok(());
        }

        let mut evaluations =
            Vec::with_capacity(argument_nodes.len() + usize::from(receiver_node.is_some()));
        if let Some(receiver) = receiver_node {
            evaluations.push(receiver);
        }
        evaluations.extend(argument_nodes);
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(invoke),
            scope,
            stack,
        )
    }

    fn yield_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let arguments = node
            .named_child(0)
            .map(runtime_expression_children)
            .unwrap_or_default();
        let boundary = if arguments.is_empty() {
            entry
        } else {
            self.point(builder, node, Vec::new())?
        };
        for (capability, kind, detail) in [
            (
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "Ruby yield dispatches to an ambient block and is not emitted as an ordinary call site",
            ),
            (
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unknown,
                "yielded block break, next, return, redo, and LocalJumpError propagation require dynamic invocation context",
            ),
            (
                SemanticCapability::Values,
                SemanticGapKind::Unknown,
                "yield argument, block parameter, and result bindings require value refinement",
            ),
        ] {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                capability,
                kind,
                detail,
            )?;
        }
        self.edge(builder, boundary, next)?;
        self.abrupt(builder, boundary, scope, CompletionKind::Throw, None, stack)?;
        if arguments.is_empty() {
            return Ok(());
        }
        self.schedule_expressions(
            builder,
            entry,
            &arguments,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    fn ruby_call_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        call_site: CallSiteId,
        receiver: Option<&str>,
        method: Option<&str>,
        has_block: bool,
    ) -> Result<(), RubyLoweringError> {
        if has_block && method != Some("define_method") {
            self.session.add_gap_with_impacts(
                builder,
                point,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DeferredExecution,
                SemanticGapImpacts::CALL_EVALUATION,
                SemanticGapKind::Unknown,
                "an attached Ruby block is a separate callable whose invocation timing depends on the callee",
            )?;
        }
        if matches!(method, Some("send" | "public_send")) {
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::Point,
                SemanticCapability::CallableReferences,
                SemanticGapKind::Unsupported,
                "Ruby dynamic send method-name conversion and visibility-sensitive lookup are not statically bound",
            )?;
        }
        if method == Some("define_method") {
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::Point,
                SemanticCapability::CallableReferences,
                SemanticGapKind::Unknown,
                "define_method publishes a dynamically named callable target",
            )?;
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DeferredExecution,
                SemanticGapKind::Unknown,
                "the define_method block becomes a method body and is not executed at definition time",
            )?;
        }
        if receiver == Some("Fiber") && matches!(method, Some("new" | "yield")) {
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::GeneratorSuspension,
                SemanticGapKind::Unknown,
                "Fiber creation or yield crosses a suspension/resumption boundary",
            )?;
        }
        if matches!(receiver, Some("Thread" | "Ractor")) && method == Some("new") {
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::ConcurrentSpawn,
                SemanticGapKind::Unknown,
                "Thread.new or Ractor.new may execute its block concurrently",
            )?;
        }
        Ok(())
    }

    fn route_call_exceptional(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        exceptional: ProgramPointId,
        normal_next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let departure = if normal_next.kind == ControlEdgeKind::Exceptional {
            let relay = self.point_from(builder, exceptional, Vec::new())?;
            self.edge(builder, exceptional, EdgeTarget::normal(relay))?;
            relay
        } else {
            exceptional
        };
        self.abrupt(
            builder,
            departure,
            scope,
            CompletionKind::Throw,
            None,
            stack,
        )
    }

    fn callable_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), RubyLoweringError> {
        let result = self.value(builder, entry, SemanticValueKind::Callable)?;
        let metadata = self.metadata(entry)?;
        self.append_effect(
            builder,
            entry,
            SemanticEffect::CallableCreation {
                result,
                callable: CallableValue {
                    kind: CallableReferenceKind::Lambda,
                    targets: CallableTargetResolution::Unknown,
                    target_evidence: metadata.evidence,
                    bound_receiver: None,
                    environment: None,
                },
            },
        )?;
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Value(result),
            SemanticCapability::CallableReferences,
            SemanticGapKind::Unknown,
            if matches!(node.kind(), "block" | "do_block") {
                "attached Ruby block target and capture environment are published as a separate closure procedure"
            } else {
                "nested Ruby callable target mapping is not yet published"
            },
        )?;
        self.edge(builder, entry, next)
    }

    fn type_declaration(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "Ruby class, module, or singleton-class body execution is represented by a separate initializer without a stitched declaration-site transfer",
        )?;
        let prefix = match node.kind() {
            "class" => node
                .child_by_field_name("superclass")
                .and_then(first_runtime_named_child),
            "singleton_class" => node.child_by_field_name("value"),
            _ => None,
        };
        if let Some(prefix) = prefix {
            stack.push(Work::Expression {
                node: prefix,
                entry,
                next,
                scope,
            });
            Ok(())
        } else {
            self.edge(builder, entry, next)
        }
    }

    fn deferred_lifecycle_block(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), RubyLoweringError> {
        for (capability, detail) in [
            (
                SemanticCapability::DeferredExecution,
                "Ruby BEGIN/END lifecycle timing is outside ordinary source-order execution",
            ),
            (
                SemanticCapability::Calls,
                "calls inside a BEGIN/END lifecycle body are withheld from the surrounding callable",
            ),
        ] {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                capability,
                SemanticGapKind::Unsupported,
                detail,
            )?;
        }
        if node.kind() == "begin_block" {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unsupported,
                "BEGIN execution occurs while the file is being loaded, not at this lexical statement position",
            )?;
        }
        self.edge(builder, entry, next)
    }

    fn boolean_value(
        &mut self,
        _builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        stack.push(Work::Condition {
            node,
            entry,
            when_true: EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalTrue,
            },
            when_false: EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
            scope,
        });
        Ok(())
    }

    fn implicit_operator(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let operator = node
            .child_by_field_name("operator")
            .and_then(|operator| node_text(self.source, operator));
        if operator == Some("defined?") {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unsupported,
                "defined? inspects syntax without ordinarily evaluating its operand",
            )?;
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "defined? behavior depends on the structured operand category",
            )?;
            return self.edge(builder, entry, next);
        }
        let terminal = self.point(builder, node, Vec::new())?;
        if matches!(operator, Some("!" | "not")) {
            self.negation_gaps(builder, terminal)?;
        } else {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "Ruby operators dispatch through methods that are not emitted as synthetic call sites",
            )?;
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "operator dispatch and coercion may raise",
            )?;
        }
        self.edge(builder, terminal, next)?;
        let operands = match node.kind() {
            "binary" => {
                let mut nodes = children_by_field_name(node, "left");
                nodes.extend(children_by_field_name(node, "right"));
                nodes
            }
            _ => children_by_field_name(node, "operand"),
        };
        self.schedule_expressions(
            builder,
            entry,
            &operands,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    fn negation_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
    ) -> Result<(), RubyLoweringError> {
        for (capability, kind, detail) in [
            (
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "Ruby !/not may dispatch through an overrideable ! method and is not emitted as a synthetic call site",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "an overrideable Ruby negation method may raise",
            ),
            (
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unknown,
                "negation branch selection may depend on overrideable Ruby method behavior",
            ),
        ] {
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::Point,
                capability,
                kind,
                detail,
            )?;
        }
        Ok(())
    }

    fn assignment(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let left = required_field(node, "left")?;
        let right = required_field(node, "right")?;
        let operator = node
            .child_by_field_name("operator")
            .and_then(|operator| node_text(self.source, operator));
        let short_circuit = matches!(operator, Some("||=" | "&&="));
        let dispatching_target = assignment_target_dispatches(left);
        let safe_navigation = left.kind() == "call"
            && left
                .child_by_field_name("operator")
                .and_then(|operator| node_text(self.source, operator))
                == Some("&.");
        let terminal = self.point(builder, node, Vec::new())?;
        let merge = if short_circuit || safe_navigation {
            Some(self.point(builder, node, Vec::new())?)
        } else {
            None
        };
        self.add_gap(
            builder,
            merge.unwrap_or(terminal),
            SemanticGapSubject::Point,
            SemanticCapability::Values,
            SemanticGapKind::Unknown,
            "Ruby assignment target and assigned value are not yet connected by value-flow rows",
        )?;
        if node.kind() == "operator_assignment" && !short_circuit {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "Ruby operator assignment may dispatch through reader, operator, and writer methods",
            )?;
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "Ruby operator-assignment dispatch and coercion may raise",
            )?;
        }
        self.edge(
            builder,
            terminal,
            merge.map(EdgeTarget::normal).unwrap_or(next),
        )?;
        if let Some(merge) = merge {
            self.edge(builder, merge, next)?;
        }

        let target_evaluations = assignment_target_runtime_nodes(left);
        if short_circuit || safe_navigation {
            let right_entry = self.point(builder, right, Vec::new())?;
            let operator_decision = if short_circuit {
                let decision = self.point(builder, left, Vec::new())?;
                let (right_kind, bypass_kind) = if operator == Some("&&=") {
                    (
                        ControlEdgeKind::ConditionalTrue,
                        ControlEdgeKind::ConditionalFalse,
                    )
                } else {
                    (
                        ControlEdgeKind::ConditionalFalse,
                        ControlEdgeKind::ConditionalTrue,
                    )
                };
                self.edge(
                    builder,
                    decision,
                    EdgeTarget {
                        point: right_entry,
                        kind: right_kind,
                    },
                )?;
                self.edge(
                    builder,
                    decision,
                    EdgeTarget {
                        point: merge.expect("short-circuit assignment has a merge"),
                        kind: bypass_kind,
                    },
                )?;
                Some(decision)
            } else {
                None
            };

            let first_decision = if safe_navigation {
                let decision = self.point(builder, left, Vec::new())?;
                self.edge(
                    builder,
                    decision,
                    EdgeTarget {
                        point: operator_decision.unwrap_or(right_entry),
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                )?;
                self.edge(
                    builder,
                    decision,
                    EdgeTarget {
                        point: merge.expect("safe-navigation assignment has a merge"),
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                )?;
                decision
            } else {
                operator_decision.expect("special assignment has a decision")
            };

            if dispatching_target && (node.kind() != "operator_assignment" || short_circuit) {
                self.assignment_dispatch_gaps(
                    builder,
                    operator_decision.unwrap_or(terminal),
                    short_circuit,
                )?;
            }
            stack.push(Work::Expression {
                node: right,
                entry: right_entry,
                next: EdgeTarget::normal(terminal),
                scope,
            });
            self.schedule_expressions(
                builder,
                entry,
                &target_evaluations,
                EdgeTarget::normal(first_decision),
                scope,
                stack,
            )
        } else {
            if dispatching_target && node.kind() != "operator_assignment" {
                self.assignment_dispatch_gaps(builder, terminal, false)?;
            }
            let mut evaluations = target_evaluations;
            evaluations.push(right);
            self.schedule_expressions(
                builder,
                entry,
                &evaluations,
                EdgeTarget::normal(terminal),
                scope,
                stack,
            )
        }
    }

    fn assignment_dispatch_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        short_circuit: bool,
    ) -> Result<(), RubyLoweringError> {
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            if short_circuit {
                "Ruby short-circuit attribute or element assignment invokes reader and writer methods that are not emitted as synthetic call sites"
            } else {
                "Ruby attribute or element assignment invokes reader or writer methods that are not emitted as synthetic call sites"
            },
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            "Ruby attribute or element assignment dispatch and coercion may raise",
        )
    }

    fn callable_table_mutation(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), RubyLoweringError> {
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::CallableReferences,
            SemanticGapKind::Unsupported,
            if node.kind() == "alias" {
                "Ruby alias mutates the current callable table without evaluating its method-name operands"
            } else {
                "Ruby undef mutates the current callable table without evaluating its method-name operands"
            },
        )?;
        self.edge(builder, entry, next)
    }

    fn element_reference(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let terminal = self.point(builder, node, Vec::new())?;
        self.add_gap(
            builder,
            terminal,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "Ruby element lookup dispatches through [] and is not emitted as a synthetic call site",
        )?;
        self.add_gap(
            builder,
            terminal,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            "element lookup and index coercion may raise",
        )?;
        self.edge(builder, terminal, next)?;
        let object = required_field(node, "object")?;
        let mut evaluations = vec![object];
        evaluations.extend(named_children(node).into_iter().filter(|child| {
            child.id() != object.id() && child.kind() != "block" && child.kind() != "do_block"
        }));
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    fn ambiguous_identifier(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let name = node_text(self.source, node).unwrap_or_default();
        if self.local_bindings.is_active_at(name, node.start_byte()) {
            return self.edge(builder, entry, next);
        }
        self.bare_call_expression(builder, node, entry, next, scope, stack)
    }

    fn bare_call_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        invoke: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let callee = self.value(builder, invoke, SemanticValueKind::Callable)?;
        let result = self.value(builder, invoke, SemanticValueKind::Temporary)?;
        let thrown = self.value(builder, invoke, SemanticValueKind::Exception)?;
        let resolution = CallableTargetResolution::Unknown;
        let metadata = self.metadata(invoke)?;
        self.append_effect(
            builder,
            invoke,
            SemanticEffect::CallableReference {
                result: callee,
                callable: CallableValue {
                    kind: CallableReferenceKind::Function,
                    targets: resolution.clone(),
                    target_evidence: metadata.evidence,
                    bound_receiver: None,
                    environment: None,
                },
            },
        )?;
        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver: None,
                arguments: Box::new([]),
                result: Some(result),
                thrown: Some(thrown),
                declared_targets: resolution.clone(),
                normal_continuation: normal,
                exceptional_continuation: exceptional,
            },
        )?;
        self.edge(builder, invoke, EdgeTarget::normal(normal))?;
        self.edge(
            builder,
            invoke,
            EdgeTarget {
                point: exceptional,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;
        self.edge(builder, normal, next)?;
        self.route_call_exceptional(builder, exceptional, next, scope, stack)?;
        self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;
        self.add_gap(
            builder,
            invoke,
            SemanticGapSubject::CallSite(call_site),
            SemanticCapability::DynamicDispatch,
            SemanticGapKind::Unknown,
            "bare Ruby calls dispatch through the implicit receiver and may use method_missing; complete target coverage requires runtime refinement",
        )
    }

    fn unsupported_super(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let boundary = self.point(builder, node, Vec::new())?;
        for (capability, detail) in [
            (
                SemanticCapability::Calls,
                "Ruby super target and implicit argument forwarding require method-owner dispatch context",
            ),
            (
                SemanticCapability::Values,
                "super actual/formal and receiver bindings are not represented",
            ),
        ] {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                capability,
                SemanticGapKind::Unsupported,
                detail,
            )?;
        }
        self.edge(builder, boundary, next)?;
        self.abrupt(builder, boundary, scope, CompletionKind::Throw, None, stack)?;
        let arguments = call_arguments(node);
        self.schedule_expressions(
            builder,
            entry,
            &arguments,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    fn schedule_statements(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        if children.is_empty() {
            return self.edge(builder, entry, next);
        }
        let entries = children
            .iter()
            .map(|child| self.statement_point(builder, *child))
            .collect::<Result<Vec<_>, _>>()?;
        self.edge(builder, entry, EdgeTarget::normal(entries[0]))?;
        for index in (0..children.len()).rev() {
            let child_next = entries
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next);
            stack.push(Work::Statement {
                node: children[index],
                entry: entries[index],
                next: child_next,
                scope,
            });
        }
        Ok(())
    }

    fn prepare_statements(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<Option<ProgramPointId>, RubyLoweringError> {
        if children.is_empty() {
            return Ok(None);
        }
        let entries = children
            .iter()
            .map(|child| self.statement_point(builder, *child))
            .collect::<Result<Vec<_>, _>>()?;
        for index in (0..children.len()).rev() {
            let child_next = entries
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next);
            stack.push(Work::Statement {
                node: children[index],
                entry: entries[index],
                next: child_next,
                scope,
            });
        }
        Ok(entries.first().copied())
    }

    fn schedule_statements_reusing_entry(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let Some((first, rest)) = children.split_first() else {
            return self.edge(builder, entry, next);
        };
        let mut entries = Vec::with_capacity(children.len());
        entries.push(entry);
        entries.extend(
            rest.iter()
                .map(|child| self.statement_point(builder, *child))
                .collect::<Result<Vec<_>, _>>()?,
        );
        for index in (0..children.len()).rev() {
            let child_next = entries
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next);
            stack.push(Work::Statement {
                node: if index == 0 { *first } else { children[index] },
                entry: entries[index],
                next: child_next,
                scope,
            });
        }
        Ok(())
    }

    fn statement_point(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<ProgramPointId, RubyLoweringError> {
        if matches!(node.kind(), "return" | "break" | "next")
            && let Some(argument) = node.named_child(0)
        {
            self.point_before(builder, node, argument)
        } else if matches!(node.kind(), "if" | "unless" | "elsif" | "while" | "until")
            && let Some(condition) = node.child_by_field_name("condition")
        {
            self.point_through(builder, node, condition, Vec::new())
        } else {
            self.point(builder, node, Vec::new())
        }
    }

    fn schedule_expressions(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        self.schedule_expressions_with_first_edge(
            builder,
            entry,
            children,
            next,
            ControlEdgeKind::Normal,
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn schedule_expressions_with_first_edge(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        first_edge_kind: ControlEdgeKind,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        if children.is_empty() {
            return self.edge(
                builder,
                entry,
                EdgeTarget {
                    point: next.point,
                    kind: first_edge_kind,
                },
            );
        }
        let entries = children
            .iter()
            .map(|child| self.point(builder, *child, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.edge(
            builder,
            entry,
            EdgeTarget {
                point: entries[0],
                kind: first_edge_kind,
            },
        )?;
        for index in (0..children.len()).rev() {
            let child_next = entries
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next);
            stack.push(Work::Expression {
                node: children[index],
                entry: entries[index],
                next: child_next,
                scope,
            });
        }
        Ok(())
    }

    fn abrupt(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        scope: ScopeFrameId,
        kind: CompletionKind,
        label: Option<&str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let Some(route) = builder.resolve_completion(scope, &CompletionRequest::new(kind, label))
        else {
            if matches!(kind, CompletionKind::Break | CompletionKind::Continue) {
                self.add_gap(
                    builder,
                    from,
                    SemanticGapSubject::Point,
                    SemanticCapability::NonLocalControl,
                    SemanticGapKind::Unsupported,
                    "Ruby abrupt completion has no matching represented target",
                )?;
                return Ok(());
            }
            return Err(RubyLoweringError::Invalid(format!(
                "{kind:?} completion has no structured continuation"
            )));
        };
        self.route(builder, from, &route, stack)
    }

    fn route(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        route: &CompletionRoute,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RubyLoweringError> {
        let target = self.route_target(builder, route, stack)?;
        self.edge(builder, from, target)
    }

    fn route_target(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        route: &CompletionRoute,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<EdgeTarget, RubyLoweringError> {
        if route.cleanups().is_empty() {
            return Ok(EdgeTarget {
                point: route.destination().target(),
                kind: route.destination().edge_kind(),
            });
        }

        let mut next = EdgeTarget {
            point: route.destination().target(),
            kind: route.destination().edge_kind(),
        };
        let mut first = None;
        for index in (0..route.cleanups().len()).rev() {
            let region_id = route.cleanups()[index];
            let region = *self
                .cleanups
                .iter()
                .find(|region| region.id == region_id)
                .ok_or_else(|| RubyLoweringError::Invalid("missing cleanup region".into()))?;
            let metadata = self.mapping(builder, region.body)?;
            let (cleanup_entry, created) =
                builder.cleanup_specialization(route, index, metadata.source, metadata.evidence)?;
            if created {
                self.session.register_point(
                    cleanup_entry,
                    metadata,
                    "cleanup specialization broke dense point allocation",
                )?;
                stack.push(Work::Statement {
                    node: region.body,
                    entry: cleanup_entry,
                    next,
                    scope: region.outer_scope,
                });
            }
            next = EdgeTarget {
                point: cleanup_entry,
                kind: ControlEdgeKind::Cleanup,
            };
            first = Some(cleanup_entry);
        }
        Ok(EdgeTarget {
            point: first.expect("route with cleanup regions has an entry"),
            kind: ControlEdgeKind::Cleanup,
        })
    }

    fn resolution_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        callee: ValueId,
        call_site: CallSiteId,
        resolution: &CallableTargetResolution,
    ) -> Result<(), RubyLoweringError> {
        let kind = match resolution {
            CallableTargetResolution::Proven(_) => return Ok(()),
            CallableTargetResolution::Ambiguous(_) => SemanticGapKind::Ambiguous,
            CallableTargetResolution::Unknown => SemanticGapKind::Unknown,
            CallableTargetResolution::Unsupported => SemanticGapKind::Unsupported,
            CallableTargetResolution::Unproven(_) => SemanticGapKind::Unproven,
            CallableTargetResolution::ExceededBudget(_) => SemanticGapKind::ExceededBudget,
        };
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Value(callee),
            SemanticCapability::CallableReferences,
            kind,
            "callable target requires whole-program Ruby dispatch refinement",
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::CallSite(call_site),
            SemanticCapability::Calls,
            kind,
            "call target requires whole-program Ruby dispatch refinement",
        )
    }

    fn point(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        effects: Vec<SemanticEffect>,
    ) -> Result<ProgramPointId, RubyLoweringError> {
        let metadata = self.mapping(builder, node)?;
        self.add_point_with_metadata(builder, metadata, effects)
    }

    fn point_through(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        start: Node<'tree>,
        end: Node<'tree>,
        effects: Vec<SemanticEffect>,
    ) -> Result<ProgramPointId, RubyLoweringError> {
        let range = (start.start_byte(), end.end_byte());
        let occurrence = self.session.next_source_occurrence(range.0, range.1);
        let anchor =
            source_anchor_between(start, end, occurrence).map_err(RubyLoweringError::Invalid)?;
        let metadata = self.add_mapping(builder, anchor)?;
        self.add_point_with_metadata(builder, metadata, effects)
    }

    fn point_before(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        child: Node<'tree>,
    ) -> Result<ProgramPointId, RubyLoweringError> {
        let range = (node.start_byte(), child.start_byte());
        let occurrence = self.session.next_source_occurrence(range.0, range.1);
        let anchor =
            callable_source_anchor(node, child, occurrence).map_err(RubyLoweringError::Invalid)?;
        let metadata = self.add_mapping(builder, anchor)?;
        self.add_point_with_metadata(builder, metadata, Vec::new())
    }

    fn point_from(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        effects: Vec<SemanticEffect>,
    ) -> Result<ProgramPointId, RubyLoweringError> {
        let metadata = self.metadata(source_point)?;
        self.add_point_with_metadata(builder, metadata, effects)
    }

    fn add_point_with_metadata(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        metadata: PointMetadata,
        effects: Vec<SemanticEffect>,
    ) -> Result<ProgramPointId, RubyLoweringError> {
        self.session.add_point(builder, metadata, effects)
    }

    fn mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, RubyLoweringError> {
        let range = node.byte_range();
        let occurrence = self.session.next_source_occurrence(range.start, range.end);
        let anchor = source_anchor(node, occurrence).map_err(RubyLoweringError::Invalid)?;
        self.add_mapping(builder, anchor)
    }

    fn add_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        anchor: SourceAnchor,
    ) -> Result<PointMetadata, RubyLoweringError> {
        self.add_mapping_with_kind(builder, anchor, SourceMappingKind::Exact)
    }

    fn add_mapping_with_kind(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        anchor: SourceAnchor,
        mapping_kind: SourceMappingKind,
    ) -> Result<PointMetadata, RubyLoweringError> {
        self.session.add_mapping(builder, anchor, mapping_kind)
    }

    fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, RubyLoweringError> {
        self.session.metadata(point)
    }

    fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, RubyLoweringError> {
        self.session.add_value(builder, point, kind)
    }

    fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), RubyLoweringError> {
        self.session.append_effect(builder, point, effect)
    }

    fn add_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        kind: SemanticGapKind,
        detail: &str,
    ) -> Result<(), RubyLoweringError> {
        self.session
            .add_gap(builder, point, subject, capability, kind, detail)?;
        Ok(())
    }

    fn edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target: EdgeTarget,
    ) -> Result<(), RubyLoweringError> {
        self.session
            .add_edge(builder, source_point, target.point, target.kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_method(source: &str) -> (tree_sitter::Tree, usize) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_ruby::LANGUAGE.into())
            .expect("Ruby grammar is valid");
        let tree = parser.parse(source, None).expect("source parses");
        let method_index = named_children(tree.root_node())
            .into_iter()
            .position(|node| node.kind() == "method")
            .expect("fixture has a method");
        (tree, method_index)
    }

    fn descendants_by_kind<'tree>(node: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
        let mut matches = Vec::new();
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            if current.kind() == kind {
                matches.push(current);
            }
            stack.extend(named_children(current).into_iter().rev());
        }
        matches
    }

    #[test]
    fn local_binding_collection_honors_pre_cancelled_requests() {
        let source = "def sample(value)\n  assigned = value\nend\n";
        let (tree, method_index) = parsed_method(source);
        let method = named_children(tree.root_node())[method_index];
        let body = method.child_by_field_name("body").unwrap_or(method);
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        match collect_local_bindings(
            source,
            method,
            body,
            None,
            &SemanticBudget::default(),
            &cancellation,
        ) {
            Err(RubyLoweringError::Cancelled(work)) => {
                assert_eq!(*work, SemanticWork::default());
            }
            _ => panic!("pre-cancelled binding collection must stop at its first checkpoint"),
        }
    }

    #[test]
    fn local_binding_collection_charges_iterative_visits_deterministically() {
        let source = "def sample(value)\n  assigned = value\nend\n";
        let (tree, method_index) = parsed_method(source);
        let method = named_children(tree.root_node())[method_index];
        let body = method.child_by_field_name("body").unwrap_or(method);
        let mut limits = SemanticWork::uniform(usize::MAX);
        limits.nested_entries = 1;
        let budget = SemanticBudget::new(limits).expect("all limits are positive");

        match collect_local_bindings(
            source,
            method,
            body,
            None,
            &budget,
            &CancellationToken::default(),
        ) {
            Err(RubyLoweringError::Budget(exceeded, work)) => {
                assert_eq!(exceeded.dimension(), SemanticBudgetDimension::NestedEntries);
                assert_eq!(exceeded.limit(), 1);
                assert_eq!(exceeded.attempted(), 2);
                assert_eq!(work.nested_entries, 2);
            }
            _ => panic!("binding traversal must charge every iterative node visit"),
        }
    }

    #[test]
    fn local_binding_timeline_activates_assignment_names_in_source_order() {
        let source = "def caller\n  target\n  target = 1\n  target\nend\n";
        let (tree, method_index) = parsed_method(source);
        let method = named_children(tree.root_node())[method_index];
        let body = method.child_by_field_name("body").unwrap_or(method);
        let collection = collect_local_bindings(
            source,
            method,
            body,
            None,
            &SemanticBudget::default(),
            &CancellationToken::default(),
        )
        .expect("binding collection succeeds");
        let targets = descendants_by_kind(body, "identifier")
            .into_iter()
            .filter(|node| node_text(source, *node) == Some("target"))
            .collect::<Vec<_>>();

        assert_eq!(targets.len(), 3);
        assert!(
            !collection
                .timeline
                .is_active_at("target", targets[0].start_byte())
        );
        assert!(
            collection
                .timeline
                .is_active_at("target", targets[1].start_byte())
        );
        assert!(
            collection
                .timeline
                .is_active_at("target", targets[2].start_byte())
        );
    }

    #[test]
    fn default_expression_assignments_activate_bindings_before_the_body() {
        let source = "def sample(value = (default_binding = 1))\n  default_binding\nend\n";
        let (tree, method_index) = parsed_method(source);
        let method = named_children(tree.root_node())[method_index];
        let body = method.child_by_field_name("body").unwrap_or(method);
        let collection = collect_local_bindings(
            source,
            method,
            body,
            None,
            &SemanticBudget::default(),
            &CancellationToken::default(),
        )
        .expect("binding collection succeeds");
        let body_read = descendants_by_kind(body, "identifier")
            .into_iter()
            .find(|node| node_text(source, *node) == Some("default_binding"))
            .expect("method body contains the default-expression binding read");

        assert!(
            collection
                .timeline
                .is_active_at("default_binding", body_read.start_byte())
        );
    }

    #[test]
    fn nested_callable_inherits_only_bindings_active_at_creation() {
        for (source, expected_capture) in [
            (
                "def caller\n  closure = -> { target }\n  target = 1\nend\n",
                false,
            ),
            (
                "def caller\n  target = -> { target; target = 1 }\nend\n",
                true,
            ),
        ] {
            let (tree, method_index) = parsed_method(source);
            let method = named_children(tree.root_node())[method_index];
            let method_body = method.child_by_field_name("body").unwrap_or(method);
            let lambda = descendants_by_kind(method_body, "lambda")[0];
            let lambda_body = lambda.child_by_field_name("body").unwrap_or(lambda);
            let parent = collect_local_bindings(
                source,
                method,
                method_body,
                None,
                &SemanticBudget::default(),
                &CancellationToken::default(),
            )
            .expect("parent binding collection succeeds");
            let child = collect_local_bindings(
                source,
                lambda,
                lambda_body,
                Some((&parent.timeline, lambda.start_byte())),
                &SemanticBudget::default(),
                &CancellationToken::default(),
            )
            .expect("child binding collection succeeds");
            let first_target = descendants_by_kind(lambda_body, "identifier")
                .into_iter()
                .find(|node| node_text(source, *node) == Some("target"))
                .expect("lambda contains target identifier");

            assert_eq!(
                child
                    .timeline
                    .is_active_at("target", first_target.start_byte()),
                expected_capture
            );
        }
    }
}
