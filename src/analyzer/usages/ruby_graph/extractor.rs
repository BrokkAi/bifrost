use crate::analyzer::ruby::{
    RubyFieldScope, extract_name_segments, parse_ruby_tree, ruby_variable_field_name,
};
use crate::analyzer::usages::common::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::hash::HashSet;
use std::collections::BTreeSet;
use tree_sitter::Node;

use super::hits::record_usage_hit;
use super::resolver::{
    ExplicitReceiverLookup, FactoryInferenceFrame, FactoryInferenceKey, FactoryMethodOutcome,
    ReceiverMode, ReceiverType, RubyMethodLookupMode, RubySemanticIndex, RubyTargetKind,
    RubyTargetSpec, ruby_method_lookup_mode_matches,
};
use super::syntax::{
    constant_hit_node, is_call_method_identifier, is_declaration_constant,
    is_declaration_identifier, method_receiver_mode, node_text, symbol_or_string_value,
};
pub(super) struct RubyFileScan<'a> {
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) semantic: &'a RubySemanticIndex<'a>,
    pub(super) support: &'a crate::analyzer::DefinitionLookupIndex,
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) visible_files: HashSet<ProjectFile>,
    pub(super) spec: &'a RubyTargetSpec,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) saw_unproven_match: &'a mut bool,
}

impl RubyFileScan<'_> {
    pub(super) fn scan(&mut self, root: Node<'_>) {
        let mut state = RubyWalkState {
            scan: self,
            locals: LocalInferenceEngine::new(LocalInferenceConfig::default()),
            lexical_stack: Vec::new(),
            method_stack: Vec::new(),
            exits: Vec::new(),
        };
        walk_tree_iterative(
            root,
            &mut state,
            |node, state| state.enter(node),
            |state| state.exit(),
        );
    }
}

enum RubyExit {
    Lexical,
    Method,
    LocalScope,
}

struct RubyWalkState<'a, 'b> {
    scan: &'a mut RubyFileScan<'b>,
    locals: LocalInferenceEngine<String>,
    lexical_stack: Vec<String>,
    method_stack: Vec<ReceiverMode>,
    exits: Vec<RubyExit>,
}

impl RubyWalkState<'_, '_> {
    fn enter(&mut self, node: Node<'_>) -> TreeWalkAction {
        match node.kind() {
            "class" | "module" => {
                self.record_superclass_reference(node);
                if let Some(owner) = self.type_owner(node) {
                    self.lexical_stack.push(owner);
                    self.exits.push(RubyExit::Lexical);
                    self.record_reference(node);
                    return TreeWalkAction::DescendWithExit;
                }
            }
            "method" | "singleton_method" => {
                self.locals.enter_scope();
                self.seed_parameter_shadows(node);
                self.method_stack.push(method_receiver_mode(node));
                self.exits.push(RubyExit::Method);
                return TreeWalkAction::DescendWithExit;
            }
            "singleton_class" => {
                self.locals.enter_scope();
                self.method_stack.push(ReceiverMode::Class);
                self.exits.push(RubyExit::Method);
                return TreeWalkAction::DescendWithExit;
            }
            "block" | "do_block" => {
                self.locals.enter_scope();
                self.exits.push(RubyExit::LocalScope);
                return TreeWalkAction::DescendWithExit;
            }
            "assignment" => self.seed_assignment(node),
            _ => {}
        }
        self.record_reference(node);
        TreeWalkAction::Descend
    }

    fn exit(&mut self) {
        match self.exits.pop() {
            Some(RubyExit::Lexical) => {
                self.lexical_stack.pop();
            }
            Some(RubyExit::Method) => {
                self.method_stack.pop();
                self.locals.exit_scope();
            }
            Some(RubyExit::LocalScope) => {
                self.locals.exit_scope();
            }
            None => {}
        }
    }

    fn type_owner(&self, node: Node<'_>) -> Option<String> {
        ruby_type_owner(
            self.scan.semantic,
            self.scan.file,
            &self.scan.visible_files,
            &self.lexical_stack,
            node,
            self.scan.source,
        )
    }

    fn record_reference(&mut self, node: Node<'_>) {
        match self.scan.spec.kind {
            RubyTargetKind::TypeOrConstant => self.record_constant_reference(node),
            RubyTargetKind::Method => self.record_method_reference(node),
            RubyTargetKind::Field(_) => self.record_field_reference(node),
        }
    }

    fn record_superclass_reference(&mut self, node: Node<'_>) {
        if self.scan.spec.kind != RubyTargetKind::TypeOrConstant {
            return;
        }
        let Some(superclass) = node.child_by_field_name("superclass") else {
            return;
        };
        let mut stack = vec![superclass];
        while let Some(current) = stack.pop() {
            self.record_constant_reference(current);
            for index in (0..current.named_child_count()).rev() {
                if let Some(child) = current.named_child(index) {
                    stack.push(child);
                }
            }
        }
    }

    fn record_field_reference(&mut self, node: Node<'_>) {
        let Some(name) = ruby_variable_field_name(node, self.scan.source) else {
            return;
        };
        if name != self.scan.spec.member_name || self.is_target_field_declaration_site(node) {
            return;
        }
        let Some((owner, scope)) =
            ruby_field_reference_owner_and_scope(&self.lexical_stack, &self.method_stack, node)
        else {
            return;
        };
        if self.field_reference_matches_target(&owner, scope) {
            self.record_hit(node);
        }
    }

    fn field_reference_matches_target(&self, owner: &str, scope: RubyFieldScope) -> bool {
        if self.scan.spec.kind != RubyTargetKind::Field(scope) {
            return false;
        }
        let Some(target_owner) = self.scan.spec.field_owner.as_deref() else {
            return false;
        };
        match scope {
            RubyFieldScope::ClassVariable => {
                owner == target_owner
                    || self
                        .scan
                        .semantic
                        .ancestor_lookup_order(owner)
                        .iter()
                        .any(|ancestor| ancestor == target_owner)
            }
            RubyFieldScope::Instance | RubyFieldScope::SingletonClass => owner == target_owner,
        }
    }

    fn is_target_field_declaration_site(&self, node: Node<'_>) -> bool {
        let Some(parent) = node.parent() else {
            return false;
        };
        if !matches!(parent.kind(), "assignment" | "operator_assignment")
            || parent.child_by_field_name("left") != Some(node)
        {
            return false;
        }
        self.scan
            .analyzer
            .ranges(&self.scan.spec.target)
            .iter()
            .any(|range| {
                range.start_byte == parent.start_byte() && range.end_byte == parent.end_byte()
            })
    }

    fn record_constant_reference(&mut self, node: Node<'_>) {
        if crate::analyzer::ruby::is_ruby_autoload_symbol_argument(node, self.scan.source) {
            self.record_autoload_symbol_constant_reference(node);
            return;
        }
        if !matches!(node.kind(), "constant" | "scope_resolution") || is_declaration_constant(node)
        {
            return;
        }
        if let Some(unit) = self.scan.semantic.resolve_constant(
            self.scan.file,
            &self.scan.visible_files,
            &self.lexical_stack,
            node,
            self.scan.source,
        ) && self.scan.semantic.target_matches_constant(&unit)
        {
            self.record_hit(constant_hit_node(node));
        }
    }

    fn record_autoload_symbol_constant_reference(&mut self, node: Node<'_>) {
        let Some(name) = crate::analyzer::ruby::ruby_symbol_name(node, self.scan.source) else {
            return;
        };
        if let Some(unit) = self.scan.semantic.resolve_constant_name(
            self.scan.file,
            &self.scan.visible_files,
            &self.lexical_stack,
            &name,
        ) && self.scan.semantic.target_matches_constant(&unit)
        {
            self.record_hit(node);
        }
    }

    fn record_method_reference(&mut self, node: Node<'_>) {
        if node.kind() == "identifier" {
            self.record_bare_identifier_method_reference(node);
            return;
        }
        if node.kind() != "call" {
            return;
        }
        if let Some(dispatched_method) =
            dynamic_dispatch_target_argument(node, self.scan.source, &self.scan.spec.member_name)
        {
            self.record_method_hit_for_call_receiver(
                node,
                dispatched_method,
                ExplicitReceiverLookup::ReceiverOnly,
            );
            return;
        }
        if let Some(aliased_method) =
            alias_method_target_argument(node, self.scan.source, &self.scan.spec.member_name)
        {
            self.record_bare_method_hit_for_receiver(
                &self.enclosing_receiver().unwrap_or_else(|| ReceiverType {
                    owner_fq_name: String::new(),
                    mode: ReceiverMode::TopLevel,
                }),
                aliased_method,
            );
            return;
        }
        let Some(method) = node.child_by_field_name("method") else {
            return;
        };
        if node_text(method, self.scan.source) != self.scan.spec.member_name {
            return;
        }
        self.record_method_hit_for_call_receiver(node, method, ExplicitReceiverLookup::Bare);
    }

    fn record_bare_identifier_method_reference(&mut self, node: Node<'_>) {
        let name = node_text(node, self.scan.source);
        if name != self.scan.spec.member_name
            || self.locals.is_shadowed(name)
            || is_declaration_identifier(node)
            || is_call_method_identifier(node)
        {
            return;
        }
        match self.enclosing_receiver() {
            Some(receiver) => self.record_bare_method_hit_for_receiver(&receiver, node),
            None => {
                *self.scan.saw_unproven_match = true;
            }
        }
    }

    fn record_bare_method_hit_for_receiver(&mut self, receiver: &ReceiverType, hit_node: Node<'_>) {
        let candidates = self.scan.semantic.resolve_bare_method_candidates(
            self.scan.support,
            &self.scan.visible_files,
            receiver,
            &self.scan.spec.member_name,
        );
        self.record_method_hit_from_candidates(&candidates, hit_node);
    }

    fn record_explicit_receiver_method_hit(&mut self, receiver: &ReceiverType, hit_node: Node<'_>) {
        let candidates = self.scan.semantic.resolve_method_candidates(
            self.scan.support,
            &self.scan.visible_files,
            receiver,
            &self.scan.spec.member_name,
        );
        self.record_method_hit_from_candidates(&candidates, hit_node);
    }

    fn record_method_hit_for_call_receiver(
        &mut self,
        call: Node<'_>,
        hit_node: Node<'_>,
        explicit_receiver_lookup: ExplicitReceiverLookup,
    ) {
        let receiver_node = call.child_by_field_name("receiver");
        let receiver = match receiver_node {
            Some(receiver) => self.receiver_type(receiver),
            None => self.enclosing_receiver(),
        };
        let Some(receiver) = receiver else {
            *self.scan.saw_unproven_match = true;
            return;
        };
        match (receiver_node, explicit_receiver_lookup) {
            (Some(_), ExplicitReceiverLookup::ReceiverOnly) => {
                self.record_explicit_receiver_method_hit(&receiver, hit_node);
            }
            _ => self.record_bare_method_hit_for_receiver(&receiver, hit_node),
        }
    }

    fn record_method_hit_from_candidates(&mut self, candidates: &[CodeUnit], hit_node: Node<'_>) {
        if candidates.iter().any(|candidate| {
            candidate == &self.scan.spec.target
                || candidate.fq_name() == self.scan.spec.target.fq_name()
        }) {
            self.record_hit(hit_node);
        } else if candidates.is_empty() {
            *self.scan.saw_unproven_match = true;
        }
    }

    fn receiver_type(&self, node: Node<'_>) -> Option<ReceiverType> {
        ruby_receiver_type(
            self.scan.semantic,
            self.scan.file,
            &self.scan.visible_files,
            &self.lexical_stack,
            &self.locals,
            &self.method_stack,
            node,
            self.scan.source,
        )
    }

    fn enclosing_receiver(&self) -> Option<ReceiverType> {
        ruby_enclosing_receiver(&self.lexical_stack, &self.method_stack)
    }

    fn seed_assignment(&mut self, node: Node<'_>) {
        ruby_seed_assignment(
            self.scan.semantic,
            self.scan.file,
            &self.scan.visible_files,
            &self.lexical_stack,
            &self.method_stack,
            &mut self.locals,
            node,
            self.scan.source,
        );
    }

    fn seed_parameter_shadows(&mut self, node: Node<'_>) {
        ruby_seed_parameter_shadows(&mut self.locals, node, self.scan.source);
    }

    fn record_hit(&mut self, node: Node<'_>) {
        record_usage_hit(
            self.scan.analyzer,
            self.scan.file,
            self.scan.source,
            self.scan.line_starts,
            self.scan.hits,
            node,
        );
    }
}

pub(crate) fn is_dynamic_dispatch_method(method: Node<'_>, source: &str) -> bool {
    matches!(
        node_text(method, source),
        "send" | "__send__" | "public_send"
    )
}

fn dynamic_dispatch_target_argument<'tree>(
    node: Node<'tree>,
    source: &str,
    member: &str,
) -> Option<Node<'tree>> {
    let method = node.child_by_field_name("method")?;
    if !is_dynamic_dispatch_method(method, source) {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let first_argument = arguments.named_children(&mut cursor).next()?;
    symbol_or_string_value(first_argument, source)
        .is_some_and(|value| value == member)
        .then_some(first_argument)
}

fn alias_method_target_argument<'tree>(
    node: Node<'tree>,
    source: &str,
    member: &str,
) -> Option<Node<'tree>> {
    let method = node.child_by_field_name("method")?;
    if node_text(method, source) != "alias_method" {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let mut args = arguments.named_children(&mut cursor);
    args.next()?;
    let target_argument = args.next()?;
    symbol_or_string_value(target_argument, source)
        .is_some_and(|value| value == member)
        .then_some(target_argument)
}

pub(super) fn language_for_file(file: &ProjectFile) -> Language {
    crate::analyzer::common::language_for_file(file)
}

pub(crate) fn first_precise(
    bindings: &LocalInferenceEngine<String>,
    symbol: &str,
) -> Option<String> {
    bindings
        .resolve_symbol(symbol)
        .as_precise()
        .and_then(|targets| targets.iter().next().cloned())
}

pub(crate) fn ruby_type_owner(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    lexical_stack: &[String],
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    let name = node.child_by_field_name("name")?;
    semantic
        .resolve_constant(file, visible_files, lexical_stack, name, source)
        .filter(|unit| unit.is_class() || unit.is_module())
        .map(|unit| unit.fq_name())
        .or_else(|| {
            let mut segments = lexical_stack.to_vec();
            segments.extend(extract_name_segments(name, source));
            (!segments.is_empty()).then(|| segments.join("$"))
        })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ruby_receiver_type(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    lexical_stack: &[String],
    locals: &LocalInferenceEngine<String>,
    method_stack: &[ReceiverMode],
    node: Node<'_>,
    source: &str,
) -> Option<ReceiverType> {
    match node.kind() {
        "constant" | "scope_resolution" => {
            let unit =
                semantic.resolve_constant(file, visible_files, lexical_stack, node, source)?;
            (unit.is_class() || unit.is_module()).then(|| ReceiverType {
                owner_fq_name: unit.fq_name(),
                mode: ReceiverMode::Class,
            })
        }
        "identifier" => {
            let name = node_text(node, source);
            if let Some(owner_fq_name) = first_precise(locals, name) {
                return Some(ReceiverType {
                    owner_fq_name,
                    mode: ReceiverMode::Instance,
                });
            }
            // A known local whose type we can't pin is not a method call.
            if locals.is_shadowed(name) {
                return None;
            }
            // Otherwise a bare implicit-`self` method used as a receiver
            // (`get_foo.v`): type it by `get_foo`'s inferred return instance.
            let enclosing = ruby_enclosing_receiver(lexical_stack, method_stack)?;
            ruby_method_return_receiver_type(semantic, visible_files, &enclosing, name)
        }
        "self" => ruby_enclosing_receiver(lexical_stack, method_stack),
        "call" => ruby_constructed_receiver_type(
            semantic,
            file,
            visible_files,
            lexical_stack,
            locals,
            method_stack,
            node,
            source,
        ),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ruby_constructed_receiver_type(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    lexical_stack: &[String],
    locals: &LocalInferenceEngine<String>,
    method_stack: &[ReceiverMode],
    node: Node<'_>,
    source: &str,
) -> Option<ReceiverType> {
    let method = node.child_by_field_name("method")?;
    let method_name = node_text(method, source);
    let receiver = node.child_by_field_name("receiver")?;

    if method_name == "new" {
        return ruby_new_receiver_type(
            semantic,
            file,
            visible_files,
            lexical_stack,
            locals,
            method_stack,
            receiver,
            source,
        );
    }

    let class = ruby_receiver_type(
        semantic,
        file,
        visible_files,
        lexical_stack,
        locals,
        method_stack,
        receiver,
        source,
    )?;
    ruby_factory_return_receiver_type(semantic, visible_files, &class, method_name)
}

#[allow(clippy::too_many_arguments)]
fn ruby_new_receiver_type(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    lexical_stack: &[String],
    locals: &LocalInferenceEngine<String>,
    method_stack: &[ReceiverMode],
    receiver: Node<'_>,
    source: &str,
) -> Option<ReceiverType> {
    let class = ruby_receiver_type(
        semantic,
        file,
        visible_files,
        lexical_stack,
        locals,
        method_stack,
        receiver,
        source,
    )?;
    (class.mode == ReceiverMode::Class).then_some(ReceiverType {
        owner_fq_name: class.owner_fq_name,
        mode: ReceiverMode::Instance,
    })
}

fn ruby_factory_return_receiver_type(
    semantic: &RubySemanticIndex<'_>,
    visible_files: &HashSet<ProjectFile>,
    class: &ReceiverType,
    method_name: &str,
) -> Option<ReceiverType> {
    if class.mode != ReceiverMode::Class {
        return None;
    }
    ruby_method_return_receiver_type(semantic, visible_files, class, method_name)
}

/// Type a call whose receiver is `receiver` and whose method is `method_name` by
/// the method's inferred return instance (e.g. a factory method returning
/// `Foo.new`). Works for both class receivers (`Klass.make.x`) and the enclosing
/// instance receiver of a bare call (`get_foo.x`).
fn ruby_method_return_receiver_type(
    semantic: &RubySemanticIndex<'_>,
    visible_files: &HashSet<ProjectFile>,
    receiver: &ReceiverType,
    method_name: &str,
) -> Option<ReceiverType> {
    semantic
        .resolve_method_candidates(
            semantic.analyzer.definition_lookup_index(),
            visible_files,
            receiver,
            method_name,
        )
        .into_iter()
        .find_map(|candidate| {
            ruby_infer_method_return_instance_owner(
                semantic,
                candidate,
                receiver.owner_fq_name.clone(),
            )
            .map(|owner_fq_name| ReceiverType {
                owner_fq_name,
                mode: ReceiverMode::Instance,
            })
        })
}

fn ruby_infer_method_return_instance_owner(
    semantic: &RubySemanticIndex<'_>,
    method_unit: CodeUnit,
    invocation_owner_fq_name: String,
) -> Option<String> {
    let start = FactoryInferenceFrame {
        method: method_unit,
        invocation_owner_fq_name,
    };
    let start_key = start.key();
    if let Some(cached) = semantic.factory_return_cache.borrow().get(&start_key) {
        return cached.clone();
    }

    let mut stack = vec![start];
    let mut visited = HashSet::default();
    while let Some(frame) = stack.pop() {
        let key = frame.key();
        if let Some(cached) = semantic.factory_return_cache.borrow().get(&key) {
            if cached.is_some() {
                semantic
                    .factory_return_cache
                    .borrow_mut()
                    .insert(start_key, cached.clone());
                return cached.clone();
            }
            continue;
        }
        if !visited.insert(key.clone()) {
            semantic.factory_return_cache.borrow_mut().insert(key, None);
            continue;
        }

        match ruby_factory_method_outcome(semantic, &frame) {
            FactoryMethodOutcome::Owner(owner) => {
                semantic
                    .factory_return_cache
                    .borrow_mut()
                    .insert(key, Some(owner.clone()));
                semantic
                    .factory_return_cache
                    .borrow_mut()
                    .insert(start_key, Some(owner.clone()));
                return Some(owner);
            }
            FactoryMethodOutcome::Chain(next) => {
                if next.is_empty() {
                    semantic.factory_return_cache.borrow_mut().insert(key, None);
                } else {
                    stack.extend(next.into_iter().rev());
                }
            }
            FactoryMethodOutcome::Unknown => {
                semantic.factory_return_cache.borrow_mut().insert(key, None);
            }
        }
    }
    semantic
        .factory_return_cache
        .borrow_mut()
        .insert(start_key, None);
    None
}

impl FactoryInferenceFrame {
    fn key(&self) -> FactoryInferenceKey {
        FactoryInferenceKey {
            method: self.method.clone(),
            invocation_owner_fq_name: self.invocation_owner_fq_name.clone(),
        }
    }
}

fn ruby_factory_method_outcome(
    semantic: &RubySemanticIndex<'_>,
    frame: &FactoryInferenceFrame,
) -> FactoryMethodOutcome {
    let Some(owner) = semantic.analyzer.parent_of(&frame.method) else {
        return FactoryMethodOutcome::Unknown;
    };
    let Ok(source) = semantic
        .analyzer
        .project()
        .read_source(frame.method.source())
    else {
        return FactoryMethodOutcome::Unknown;
    };
    let Some(tree) = parse_ruby_tree(&source) else {
        return FactoryMethodOutcome::Unknown;
    };
    let ranges = semantic.analyzer.ranges(&frame.method);
    let Some(node) = ruby_method_node_for_ranges(tree.root_node(), ranges, &source) else {
        return FactoryMethodOutcome::Unknown;
    };
    let Some(expression) = ruby_tail_expression(node) else {
        return FactoryMethodOutcome::Unknown;
    };
    let expression = if expression.kind() == "assignment" {
        let Some(right) = expression.child_by_field_name("right") else {
            return FactoryMethodOutcome::Unknown;
        };
        right
    } else {
        expression
    };
    if expression.kind() != "call"
        || expression
            .child_by_field_name("method")
            .is_none_or(|method| node_text(method, &source) != "new")
    {
        return FactoryMethodOutcome::Unknown;
    }
    if expression.child_by_field_name("receiver").is_none()
        && ruby_method_lookup_mode_matches(
            semantic.ruby,
            &frame.method,
            RubyMethodLookupMode::SingletonMethod,
        )
    {
        return FactoryMethodOutcome::Owner(frame.invocation_owner_fq_name.clone());
    }
    let Some(receiver) = expression.child_by_field_name("receiver") else {
        return FactoryMethodOutcome::Unknown;
    };
    ruby_factory_new_receiver_outcome(
        semantic,
        frame.method.source(),
        &source,
        &owner.fq_name(),
        &frame.invocation_owner_fq_name,
        receiver,
    )
}

pub(super) fn ruby_method_node_for_ranges<'tree>(
    root: Node<'tree>,
    ranges: &[Range],
    source: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if ranges
            .iter()
            .any(|range| range.start_byte == node.start_byte() && range.end_byte == node.end_byte())
        {
            if matches!(node.kind(), "method" | "singleton_method" | "call") {
                return Some(node);
            }
            if let Some(call) = ruby_synthetic_method_macro_call(node, source) {
                return Some(call);
            }
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    None
}

fn ruby_synthetic_method_macro_call<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    if !matches!(node.kind(), "simple_symbol" | "string") {
        return None;
    }
    let arguments = node.parent()?;
    if arguments.kind() != "argument_list" {
        return None;
    }
    let call = arguments.parent()?;
    if call.kind() != "call" {
        return None;
    }
    let method = call.child_by_field_name("method")?;
    matches!(
        node_text(method, source),
        "attr_accessor" | "attr_reader" | "attr_writer" | "alias_method"
    )
    .then_some(call)
}

fn ruby_factory_new_receiver_outcome(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    source: &str,
    owner_fq_name: &str,
    invocation_owner_fq_name: &str,
    receiver: Node<'_>,
) -> FactoryMethodOutcome {
    let lexical_stack = ruby_lexical_stack_for_owner(owner_fq_name);
    match receiver.kind() {
        "self" => FactoryMethodOutcome::Owner(invocation_owner_fq_name.to_string()),
        "constant" | "scope_resolution" => {
            let visible_files = semantic.visible_files_from(file);
            semantic
                .resolve_constant(file, &visible_files, &lexical_stack, receiver, source)
                .filter(|unit| unit.is_class() || unit.is_module())
                .map(|unit| FactoryMethodOutcome::Owner(unit.fq_name()))
                .unwrap_or(FactoryMethodOutcome::Unknown)
        }
        "call" => ruby_factory_chained_call_outcome(
            semantic,
            file,
            source,
            &lexical_stack,
            invocation_owner_fq_name,
            receiver,
        ),
        _ => FactoryMethodOutcome::Unknown,
    }
}

fn ruby_factory_chained_call_outcome(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    source: &str,
    lexical_stack: &[String],
    invocation_owner_fq_name: &str,
    call: Node<'_>,
) -> FactoryMethodOutcome {
    let Some(method) = call.child_by_field_name("method") else {
        return FactoryMethodOutcome::Unknown;
    };
    let method_name = node_text(method, source);
    let Some(receiver) = call.child_by_field_name("receiver") else {
        return FactoryMethodOutcome::Unknown;
    };
    let Some(owner_fq_name) = ruby_factory_class_receiver_owner(
        semantic,
        file,
        source,
        lexical_stack,
        invocation_owner_fq_name,
        receiver,
    ) else {
        return FactoryMethodOutcome::Unknown;
    };
    let visible_files = semantic.visible_files_from(file);
    let class = ReceiverType {
        owner_fq_name: owner_fq_name.clone(),
        mode: ReceiverMode::Class,
    };
    let frames = semantic
        .resolve_method_candidates(
            semantic.analyzer.definition_lookup_index(),
            &visible_files,
            &class,
            method_name,
        )
        .into_iter()
        .map(|method| FactoryInferenceFrame {
            method,
            invocation_owner_fq_name: owner_fq_name.clone(),
        })
        .collect();
    FactoryMethodOutcome::Chain(frames)
}

fn ruby_factory_class_receiver_owner(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    source: &str,
    lexical_stack: &[String],
    invocation_owner_fq_name: &str,
    receiver: Node<'_>,
) -> Option<String> {
    match receiver.kind() {
        "self" => Some(invocation_owner_fq_name.to_string()),
        "constant" | "scope_resolution" => {
            let visible_files = semantic.visible_files_from(file);
            semantic
                .resolve_constant(file, &visible_files, lexical_stack, receiver, source)
                .filter(|unit| unit.is_class() || unit.is_module())
                .map(|unit| unit.fq_name())
        }
        _ => None,
    }
}

fn ruby_tail_expression(node: Node<'_>) -> Option<Node<'_>> {
    let body = node.child_by_field_name("body")?;
    let mut cursor = body.walk();
    body.named_children(&mut cursor).last()
}

fn ruby_lexical_stack_for_owner(owner_fq_name: &str) -> Vec<String> {
    let segments: Vec<_> = owner_fq_name
        .split('$')
        .filter(|segment| !segment.is_empty())
        .collect();
    (1..=segments.len())
        .map(|end| segments[..end].join("$"))
        .collect()
}

pub(crate) fn ruby_enclosing_receiver(
    lexical_stack: &[String],
    method_stack: &[ReceiverMode],
) -> Option<ReceiverType> {
    if lexical_stack.is_empty() {
        return Some(ReceiverType {
            owner_fq_name: String::new(),
            mode: ReceiverMode::TopLevel,
        });
    }

    let owner_fq_name = lexical_stack.last()?.clone();
    let mode = method_stack
        .last()
        .copied()
        .unwrap_or(ReceiverMode::Instance);
    Some(ReceiverType {
        owner_fq_name,
        mode,
    })
}

pub(crate) fn ruby_field_reference_owner_and_scope(
    lexical_stack: &[String],
    method_stack: &[ReceiverMode],
    node: Node<'_>,
) -> Option<(String, RubyFieldScope)> {
    match node.kind() {
        "class_variable" => lexical_stack
            .last()
            .cloned()
            .map(|owner| (owner, RubyFieldScope::ClassVariable)),
        "instance_variable" => {
            let owner = lexical_stack.last()?.clone();
            let scope = match method_stack.last().copied() {
                Some(ReceiverMode::Instance) => RubyFieldScope::Instance,
                Some(ReceiverMode::Class | ReceiverMode::TopLevel) | None => {
                    RubyFieldScope::SingletonClass
                }
            };
            Some((owner, scope))
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ruby_seed_assignment(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    lexical_stack: &[String],
    method_stack: &[ReceiverMode],
    locals: &mut LocalInferenceEngine<String>,
    node: Node<'_>,
    source: &str,
) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    if left.kind() != "identifier" {
        return;
    }
    let name = node_text(left, source);
    if name.is_empty() {
        return;
    }
    let resolved = node
        .child_by_field_name("right")
        .and_then(|right| {
            ruby_receiver_type(
                semantic,
                file,
                visible_files,
                lexical_stack,
                locals,
                method_stack,
                right,
                source,
            )
        })
        .filter(|receiver| receiver.mode == ReceiverMode::Instance)
        .map(|receiver| receiver.owner_fq_name);
    match resolved {
        Some(owner) => locals.seed_symbol(name.to_string(), owner),
        None => locals.declare_shadow(name.to_string()),
    }
}

pub(crate) fn ruby_seed_parameter_shadows(
    locals: &mut LocalInferenceEngine<String>,
    node: Node<'_>,
    source: &str,
) {
    if let Some(parameters) = node.child_by_field_name("parameters") {
        let mut stack = vec![parameters];
        while let Some(current) = stack.pop() {
            if current.kind() == "identifier" {
                let name = node_text(current, source);
                if !name.is_empty() {
                    locals.declare_shadow(name.to_string());
                }
                continue;
            }
            for index in (0..current.named_child_count()).rev() {
                if let Some(child) = current.named_child(index) {
                    stack.push(child);
                }
            }
        }
    }
}
