//! Ruby local-binding analysis, shared by the semantic lowering and the
//! structural spec.
//!
//! Ruby decides "local-variable read versus zero-argument bare call" lexically:
//! an identifier read is a local read when a parameter or an assignment to the
//! same name appears lexically before it inside the same method, block, or
//! lambda. This module owns that rule as a [`LocalBindingTimeline`] per
//! callable: the set of names bound on entry (parameters, inherited captures)
//! plus the byte offset at which each assigned name becomes active.
//!
//! The semantic lowering (`bifrost-analysis`, `analyzer/ruby/semantic.rs`)
//! charges every traversal step against a semantic budget and polls
//! cancellation; the structural spec runs the same collection unbudgeted while
//! building its per-file call-site context. Both cost models plug in through
//! [`LocalBindingBudget`], so there is exactly one implementation of the
//! binding rule.

use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

/// The cost and cancellation seam of the shared collection walk.
///
/// The charging points map one-to-one onto the semantic lowering's original
/// accounting: one [`enter_node`](Self::enter_node) per iterative node visit,
/// one [`before_insert`](Self::before_insert) cancellation poll per attempted
/// name insertion, and one [`charge_name`](Self::charge_name) per newly owned
/// name string.
pub trait LocalBindingBudget {
    type Error;
    /// One traversal entry: poll cancellation and charge one visited node.
    fn enter_node(&mut self) -> Result<(), Self::Error>;
    /// Poll cancellation before a name insertion is attempted.
    fn before_insert(&mut self) -> Result<(), Self::Error>;
    /// Charge the owned bytes of a newly recorded name.
    fn charge_name(&mut self, name: &str) -> Result<(), Self::Error>;
}

/// The unbudgeted cost model for per-file structural precomputation, which is
/// bounded by the extraction driver's own source-byte and fact-count limits.
#[derive(Debug, Default)]
pub struct UnboundedLocalBindingBudget;

impl LocalBindingBudget for UnboundedLocalBindingBudget {
    type Error = std::convert::Infallible;

    fn enter_node(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn before_insert(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn charge_name(&mut self, _name: &str) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// When each local name of one callable is in effect.
///
/// `entry_bindings` are bound over the whole callable (parameters, numbered
/// block parameters, inherited captures). `activations` map an assigned name
/// to the earliest byte offset of an assignment target with that name; the
/// name reads as a local at any byte at or after that offset.
#[derive(Clone, Default)]
pub struct LocalBindingTimeline {
    entry_bindings: HashSet<Box<str>>,
    activations: HashMap<Box<str>, usize>,
}

impl LocalBindingTimeline {
    pub fn is_active_at(&self, name: &str, source_byte: usize) -> bool {
        self.entry_bindings.contains(name)
            || self
                .activations
                .get(name)
                .is_some_and(|activation| *activation <= source_byte)
    }

    /// Every assignment-activated name with the byte offset at which it
    /// becomes active, in unspecified order.
    pub fn activations(&self) -> impl Iterator<Item = (&str, usize)> {
        self.activations
            .iter()
            .map(|(name, start)| (name.as_ref(), *start))
    }

    pub fn active_names_at(&self, source_byte: usize) -> Vec<&str> {
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

pub struct LocalBindingCollection {
    pub timeline: LocalBindingTimeline,
    pub has_parameter_defaults: bool,
}

fn node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    node.utf8_text(source.as_bytes()).ok()
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .collect()
}

fn children_by_field_name<'tree>(node: Node<'tree>, field: &str) -> Vec<Node<'tree>> {
    node.child_by_field_name(field).into_iter().collect()
}

struct LocalBindingCollector<'source, 'request, B: LocalBindingBudget> {
    source: &'source str,
    timeline: LocalBindingTimeline,
    has_parameter_defaults: bool,
    budget: &'request mut B,
}

impl<'source, 'request, B: LocalBindingBudget> LocalBindingCollector<'source, 'request, B> {
    fn new(source: &'source str, budget: &'request mut B) -> Self {
        Self {
            source,
            timeline: LocalBindingTimeline::default(),
            has_parameter_defaults: false,
            budget,
        }
    }

    fn visit(&mut self) -> Result<(), B::Error> {
        self.budget.enter_node()
    }

    fn insert_entry_name(&mut self, name: &str) -> Result<(), B::Error> {
        self.budget.before_insert()?;
        if self.timeline.entry_bindings.contains(name) {
            return Ok(());
        }
        if self.timeline.activations.remove(name).is_none() {
            self.budget.charge_name(name)?;
        }
        self.timeline.entry_bindings.insert(name.into());
        Ok(())
    }

    fn insert_activation(&mut self, name: &str, source_byte: usize) -> Result<(), B::Error> {
        self.budget.before_insert()?;
        if self.timeline.entry_bindings.contains(name) {
            return Ok(());
        }
        if let Some(activation) = self.timeline.activations.get_mut(name) {
            *activation = (*activation).min(source_byte);
            return Ok(());
        }
        self.budget.charge_name(name)?;
        self.timeline.activations.insert(name.into(), source_byte);
        Ok(())
    }

    fn insert_entry_identifier(&mut self, node: Node<'_>) -> Result<(), B::Error> {
        if node.kind() == "identifier"
            && let Some(name) = node_text(self.source, node)
        {
            self.insert_entry_name(name)?;
        }
        Ok(())
    }

    fn insert_activation_identifier(&mut self, node: Node<'_>) -> Result<(), B::Error> {
        if node.kind() == "identifier"
            && let Some(name) = node_text(self.source, node)
        {
            self.insert_activation(name, node.start_byte())?;
        }
        Ok(())
    }

    fn collect_parameters(&mut self, node: Node<'_>) -> Result<(), B::Error> {
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

    fn collect_assignment(&mut self, node: Node<'_>) -> Result<(), B::Error> {
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

    fn collect_pattern(&mut self, node: Node<'_>) -> Result<(), B::Error> {
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
        }
    }
}

/// The parameter list of `callable`, which for a `lambda` node hangs off the
/// block or do-block wrapper that is its body.
pub fn callable_parameters<'tree>(callable: Node<'tree>, body: Node<'tree>) -> Option<Node<'tree>> {
    callable.child_by_field_name("parameters").or_else(|| {
        (callable.kind() == "lambda")
            .then(|| body.child_by_field_name("parameters"))
            .flatten()
    })
}

/// Collect the local-binding timeline of one callable.
///
/// `callable` is the callable node (`method`, `singleton_method`, `lambda`,
/// `block`, `do_block`, or a class/module/program scope root) and `body` its
/// executable body. `inherited` seeds captures for lambdas and blocks: the
/// enclosing callable's timeline and the byte offset at which the nested
/// callable appears, so only bindings already active there are captured.
pub fn collect_local_bindings<B: LocalBindingBudget>(
    source: &str,
    callable: Node<'_>,
    body: Node<'_>,
    inherited: Option<(&LocalBindingTimeline, usize)>,
    budget: &mut B,
) -> Result<LocalBindingCollection, B::Error> {
    let mut collector = LocalBindingCollector::new(source, budget);
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
