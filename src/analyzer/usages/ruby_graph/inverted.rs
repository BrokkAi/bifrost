//! Whole-workspace inverted edge builder for Ruby.
//!
//! Ruby's query path is intentionally conservative: it emits a hit only when
//! parser and analyzer facts prove the target. The inverted path follows the same
//! rule. It records constants resolved by `RubySemanticIndex`, class-side method
//! calls such as `Klass.call`, constructor calls as `Klass.initialize`, and calls
//! through `self`, lexical receivers, factory-return inference, or locally typed
//! receivers. Unknown receivers and candidate sets with anything other than one
//! resolved declaration record unproven inbound evidence for bulk dead-code
//! analysis rather than a proven edge.

use super::extractor::{
    is_dynamic_dispatch_method, ruby_enclosing_receiver, ruby_receiver_type, ruby_seed_assignment,
    ruby_seed_parameter_shadows, ruby_type_owner,
};
use super::resolver::{ReceiverMode, ReceiverType, RubySemanticIndex};
use super::syntax::{
    is_call_method_identifier, is_declaration_constant, is_declaration_identifier,
    method_receiver_mode, node_text, symbol_or_string_value,
};
use crate::analyzer::usages::common::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdges, build_edges, parse_and_collect,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, RubyAnalyzer};
use crate::hash::HashSet;
use tree_sitter::Node;

pub(super) fn build_ruby_edges<F>(
    analyzer: &dyn IAnalyzer,
    ruby: &RubyAnalyzer,
    files: &[ProjectFile],
    nodes: &HashSet<String>,
    keep_file: F,
) -> UsageEdges
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_ruby::LANGUAGE.into();
    build_edges(files, keep_file, |file| {
        parse_and_collect(analyzer, file, nodes, &language, |parsed, collector| {
            let semantic = RubySemanticIndex::build_for_lookup(analyzer, ruby);
            let visible_files = semantic.visible_files_from(file);
            let mut scan = RubyEdgeScan {
                semantic: &semantic,
                support: analyzer.definition_lookup_index(),
                file,
                source: parsed.source.as_str(),
                visible_files,
                class_ranges: ClassRangeIndex::build(analyzer, file),
                collector,
            };
            scan.scan(parsed.tree.root_node());
        })
    })
}

struct RubyEdgeScan<'a, 'b> {
    semantic: &'a RubySemanticIndex<'a>,
    support: &'a crate::analyzer::DefinitionLookupIndex,
    file: &'a ProjectFile,
    source: &'a str,
    visible_files: HashSet<ProjectFile>,
    class_ranges: ClassRangeIndex,
    collector: &'a mut EdgeCollector<'b>,
}

impl RubyEdgeScan<'_, '_> {
    fn scan(&mut self, root: Node<'_>) {
        let mut state = RubyEdgeWalkState {
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

    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }

    fn record_unproven_name(&mut self, name: &str, node: Node<'_>) {
        self.collector
            .record_unproven_name(name, node.start_byte(), node.end_byte());
    }
}

enum RubyEdgeExit {
    Lexical,
    Method,
    LocalScope,
}

struct RubyEdgeWalkState<'scan, 'ctx, 'collector> {
    scan: &'scan mut RubyEdgeScan<'ctx, 'collector>,
    locals: LocalInferenceEngine<String>,
    lexical_stack: Vec<String>,
    method_stack: Vec<ReceiverMode>,
    exits: Vec<RubyEdgeExit>,
}

impl RubyEdgeWalkState<'_, '_, '_> {
    fn enter(&mut self, node: Node<'_>) -> TreeWalkAction {
        match node.kind() {
            "class" | "module" => {
                self.record_superclass_reference(node);
                if let Some(owner) = self.type_owner(node) {
                    self.lexical_stack.push(owner);
                    self.exits.push(RubyEdgeExit::Lexical);
                    self.record_reference(node);
                    return TreeWalkAction::DescendWithExit;
                }
            }
            "method" | "singleton_method" => {
                self.locals.enter_scope();
                self.seed_parameter_shadows(node);
                self.method_stack.push(method_receiver_mode(node));
                self.exits.push(RubyEdgeExit::Method);
                return TreeWalkAction::DescendWithExit;
            }
            "singleton_class" => {
                self.locals.enter_scope();
                self.method_stack.push(ReceiverMode::Class);
                self.exits.push(RubyEdgeExit::Method);
                return TreeWalkAction::DescendWithExit;
            }
            "block" | "do_block" => {
                self.locals.enter_scope();
                self.exits.push(RubyEdgeExit::LocalScope);
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
            Some(RubyEdgeExit::Lexical) => {
                self.lexical_stack.pop();
            }
            Some(RubyEdgeExit::Method) => {
                self.method_stack.pop();
                self.locals.exit_scope();
            }
            Some(RubyEdgeExit::LocalScope) => {
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
        self.record_constant_reference(node);
        self.record_method_reference(node);
    }

    fn record_superclass_reference(&mut self, node: Node<'_>) {
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
        ) && (unit.is_class() || unit.is_module())
        {
            self.scan.record(unit.fq_name(), node);
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
        ) && (unit.is_class() || unit.is_module())
        {
            self.scan.record(unit.fq_name(), node);
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
        let Some(method) = node.child_by_field_name("method") else {
            return;
        };
        let member = node_text(method, self.scan.source);
        if member.is_empty() {
            return;
        }
        if is_dynamic_dispatch_method(method, self.scan.source) {
            if let Some((dispatched_member, dispatched_node)) =
                dynamic_dispatch_target_argument(node, self.scan.source)
            {
                self.record_call_method_reference(
                    node,
                    &dispatched_member,
                    dispatched_node,
                    MethodLookup::Explicit,
                );
            }
            return;
        }
        self.record_call_method_reference(
            node,
            member,
            method,
            if node.child_by_field_name("receiver").is_some() {
                MethodLookup::Explicit
            } else {
                MethodLookup::Bare
            },
        );
    }

    fn record_call_method_reference(
        &mut self,
        node: Node<'_>,
        member: &str,
        hit_node: Node<'_>,
        lookup: MethodLookup,
    ) {
        let receiver_node = node.child_by_field_name("receiver");
        let receiver = match receiver_node {
            Some(receiver) => self.receiver_type(receiver),
            None => self.enclosing_receiver(node.start_byte()),
        };
        let Some(receiver) = receiver else {
            self.scan.record_unproven_name(member, hit_node);
            return;
        };
        if member == "new" && receiver.mode == ReceiverMode::Class {
            self.record_unique_method_candidate(
                self.initialize_receiver(&receiver),
                "initialize",
                hit_node,
                MethodLookup::Explicit,
            );
            return;
        }
        self.record_unique_method_candidate(receiver, member, hit_node, lookup);
    }

    fn record_bare_identifier_method_reference(&mut self, node: Node<'_>) {
        let name = node_text(node, self.scan.source);
        if name.is_empty()
            || self.locals.is_shadowed(name)
            || is_declaration_identifier(node)
            || is_call_method_identifier(node)
        {
            return;
        }
        let Some(receiver) = self.enclosing_receiver(node.start_byte()) else {
            return;
        };
        self.record_unique_method_candidate(receiver, name, node, MethodLookup::Bare);
    }

    fn record_unique_method_candidate(
        &mut self,
        receiver: ReceiverType,
        member: &str,
        node: Node<'_>,
        lookup: MethodLookup,
    ) {
        let candidates = match lookup {
            MethodLookup::Bare => self.scan.semantic.resolve_bare_method_candidates(
                self.scan.support,
                &self.scan.visible_files,
                &receiver,
                member,
            ),
            MethodLookup::Explicit => self.scan.semantic.resolve_method_candidates(
                self.scan.support,
                &self.scan.visible_files,
                &receiver,
                member,
            ),
        };
        if let Some(fqn) = unique_candidate_fqn(candidates) {
            self.scan.record(fqn, node);
        } else {
            self.scan.record_unproven_name(member, node);
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

    fn enclosing_receiver(&self, byte: usize) -> Option<ReceiverType> {
        ruby_enclosing_receiver(&self.lexical_stack, &self.method_stack).or_else(|| {
            self.scan
                .class_ranges
                .enclosing(byte)
                .map(|owner_fq_name| ReceiverType {
                    owner_fq_name: owner_fq_name.to_string(),
                    mode: ReceiverMode::Instance,
                })
        })
    }

    fn initialize_receiver(&self, receiver: &ReceiverType) -> ReceiverType {
        ReceiverType {
            owner_fq_name: receiver.owner_fq_name.clone(),
            mode: ReceiverMode::Instance,
        }
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
}

#[derive(Clone, Copy)]
enum MethodLookup {
    Bare,
    Explicit,
}

fn unique_candidate_fqn(candidates: Vec<CodeUnit>) -> Option<String> {
    if candidates.len() == 1 {
        candidates
            .into_iter()
            .next()
            .map(|candidate| candidate.fq_name())
    } else {
        None
    }
}

fn dynamic_dispatch_target_argument<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(String, Node<'tree>)> {
    let arguments = node.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let first_argument = arguments.named_children(&mut cursor).next()?;
    symbol_or_string_value(first_argument, source).map(|member| (member, first_argument))
}
