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

use crate::graph::RubyGraphSource;
use crate::graph::extractor::{
    ruby_enclosing_receiver, ruby_receiver_type, ruby_seed_assignment, ruby_seed_parameter_shadows,
    ruby_type_owner,
};
use crate::graph::resolver::{
    ReceiverMode, ReceiverType, RubySemanticIndex, resolve_constant_reference,
};
use crate::graph::scope::{RubyScopeExit, exit_scope, ruby_type_body_declaration};
use crate::graph::syntax::{
    dynamic_dispatch_target_argument, is_bare_method_reference_identifier,
    is_dynamic_dispatch_method, method_receiver_mode, node_text, ruby_call_is_same_owner,
};
use crate::graph_support::RubySource;
use crate::syntax::ruby_semantic_identifier_range;
use brokk_bifrost_core::analyzer::tree_walk::{TreeWalkAction, walk_tree_iterative};
use brokk_bifrost_core::analyzer::usages::inverted_edges::{
    ClassRangeIndex, FileEdgeScanInput, PerFileEdges, classify_reference_node,
};
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceConfig, LocalInferenceEngine,
};
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::Node;

/// One file's `caller -> callee` edges, for the whole-workspace inverted pass.
///
/// The pass's fan-out -- `build_edge_output` plus `parse_and_collect`, the
/// shared cross-language driver -- stays in `brokk-bifrost-analysis` and calls
/// this per file, so the Ruby half is a pure function of a parsed file and the
/// two sources.
pub fn scan_file(
    graph: RubyGraphSource<'_>,
    ruby: &dyn RubySource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    input: &FileEdgeScanInput<'_>,
    visible_files: HashSet<ProjectFile>,
) -> PerFileEdges {
    let semantic = RubySemanticIndex::build_for_lookup(graph, ruby);
    let mut scan = RubyEdgeScan {
        semantic: &semantic,
        support,
        file,
        visible_files,
        class_ranges: ClassRangeIndex::build(graph.index, file),
        evidence: RubyEdgeEvidence {
            source: input.source,
            input,
            edges: PerFileEdges::default(),
        },
    };
    scan.scan(input.root());
    scan.evidence.edges
}

struct RubyEdgeScan<'a> {
    semantic: &'a RubySemanticIndex<'a>,
    support: &'a dyn BoundedDefinitionLookup,
    file: &'a ProjectFile,
    visible_files: HashSet<ProjectFile>,
    class_ranges: ClassRangeIndex,
    evidence: RubyEdgeEvidence<'a>,
}

impl RubyEdgeScan<'_> {
    fn scan(&mut self, root: Node<'_>) {
        let mut state = RubyEdgeWalkState {
            scan: self,
            locals: LocalInferenceEngine::new(LocalInferenceConfig::default()),
            lexical_stack: Vec::new(),
            method_stack: Vec::new(),
            receiver_context: Vec::new(),
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

// The grammar-to-edge boundary owns token normalization and the shared ledger.
// Keep it independent of semantic lookup so source evidence can be validated
// against the released grammar before aggregation discards individual offsets.
struct RubyEdgeEvidence<'a> {
    source: &'a str,
    input: &'a FileEdgeScanInput<'a>,
    edges: PerFileEdges,
}

impl RubyEdgeEvidence<'_> {
    fn record(&mut self, callee: String, node: Node<'_>) {
        let range = ruby_semantic_identifier_range(node, self.source);
        self.edges.record_kind(
            self.input,
            callee,
            classify_reference_node(node),
            range.start_byte,
            range.end_byte,
        );
    }

    fn record_unproven_dispatch(&mut self, node: Node<'_>) {
        let range = ruby_semantic_identifier_range(node, self.source);
        for callee in self.input.inbound_callees() {
            self.edges.record_unproven(
                self.input,
                callee.clone(),
                range.start_byte,
                range.end_byte,
            );
        }
    }

    fn record_unproven_name(&mut self, name: &str, node: Node<'_>) {
        let range = ruby_semantic_identifier_range(node, self.source);
        self.edges
            .record_unproven_name(self.input, name, range.start_byte, range.end_byte);
    }
}

struct RubyEdgeWalkState<'scan, 'ctx> {
    scan: &'scan mut RubyEdgeScan<'ctx>,
    locals: LocalInferenceEngine<String>,
    lexical_stack: Vec<String>,
    method_stack: Vec<ReceiverMode>,
    receiver_context: Vec<ReceiverMode>,
    exits: Vec<RubyScopeExit>,
}

impl RubyEdgeWalkState<'_, '_> {
    fn enter(&mut self, node: Node<'_>) -> TreeWalkAction {
        if let Some(declaration) = ruby_type_body_declaration(node) {
            let owner = self.type_owner(declaration);
            if let Some(owner) = owner.as_ref() {
                self.lexical_stack.push(owner.clone());
            }
            self.receiver_context.push(ReceiverMode::Instance);
            self.exits.push(RubyScopeExit::Type {
                has_lexical_owner: owner.is_some(),
                locals: std::mem::take(&mut self.locals),
            });
            return TreeWalkAction::DescendWithExit;
        }
        match node.kind() {
            "method" | "singleton_method" => {
                let locals = std::mem::take(&mut self.locals);
                self.seed_parameter_shadows(node);
                self.method_stack.push(method_receiver_mode(
                    node,
                    self.receiver_context.last().copied(),
                ));
                self.exits.push(RubyScopeExit::Method { locals });
                return TreeWalkAction::DescendWithExit;
            }
            "singleton_class" => {
                let locals = std::mem::take(&mut self.locals);
                self.method_stack.push(ReceiverMode::Class);
                self.receiver_context.push(ReceiverMode::Class);
                self.exits.push(RubyScopeExit::SingletonClass { locals });
                return TreeWalkAction::DescendWithExit;
            }
            "block" | "do_block" => {
                self.locals.enter_scope();
                self.exits.push(RubyScopeExit::LocalScope);
                return TreeWalkAction::DescendWithExit;
            }
            "assignment" => self.seed_assignment(node),
            _ => {}
        }
        self.record_reference(node);
        TreeWalkAction::Descend
    }

    fn exit(&mut self) {
        exit_scope(
            self.exits.pop(),
            &mut self.receiver_context,
            &mut self.lexical_stack,
            &mut self.method_stack,
            &mut self.locals,
        );
    }

    fn type_owner(&self, node: Node<'_>) -> Option<String> {
        ruby_type_owner(
            self.scan.semantic,
            self.scan.file,
            &self.scan.visible_files,
            &self.lexical_stack,
            node,
            self.scan.evidence.source,
        )
    }

    fn record_reference(&mut self, node: Node<'_>) {
        self.record_constant_reference(node);
        self.record_method_reference(node);
    }

    fn record_constant_reference(&mut self, node: Node<'_>) {
        let Some(reference) = resolve_constant_reference(
            self.scan.semantic,
            self.scan.file,
            &self.scan.visible_files,
            &self.lexical_stack,
            node,
            self.scan.evidence.source,
        ) else {
            return;
        };
        if reference.unit.is_class() || reference.unit.is_module() {
            self.scan.evidence.record(reference.unit.fq_name(), node);
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
        let member = node_text(method, self.scan.evidence.source);
        if member.is_empty() {
            return;
        }
        if let Some((dispatched_member, dispatched_node)) =
            dynamic_dispatch_target_argument(node, self.scan.evidence.source)
        {
            self.record_call_method_reference(
                node,
                &dispatched_member,
                dispatched_node,
                MethodLookup::Explicit,
            );
            return;
        }
        if is_dynamic_dispatch_method(method, self.scan.evidence.source) {
            self.scan.evidence.record_unproven_dispatch(method);
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
        // A `self.method` or implicit-self (bare) call is on the current instance
        // / own class — a same-owner site (#1138). An explicit variable/constant
        // receiver stays external.
        let same_owner = ruby_call_is_same_owner(node);
        let receiver = match receiver_node {
            Some(receiver) => self.receiver_type(receiver),
            None => self.enclosing_receiver(node.start_byte()),
        };
        let Some(receiver) = receiver else {
            self.scan.evidence.record_unproven_name(member, hit_node);
            return;
        };
        if member == "new" && receiver.mode == ReceiverMode::Class {
            let overrides = self.scan.semantic.resolve_method_candidates(
                self.scan.support,
                &self.scan.visible_files,
                &receiver,
                member,
            );
            if !overrides.is_empty() {
                self.record_candidates(overrides, member, hit_node, same_owner);
                return;
            }
            self.record_unique_method_candidate(
                self.initialize_receiver(&receiver),
                "initialize",
                hit_node,
                MethodLookup::Explicit,
                same_owner,
            );
            return;
        }
        self.record_unique_method_candidate(receiver, member, hit_node, lookup, same_owner);
    }

    fn record_bare_identifier_method_reference(&mut self, node: Node<'_>) {
        let name = node_text(node, self.scan.evidence.source);
        if name.is_empty()
            || self.locals.is_shadowed(name)
            || !is_bare_method_reference_identifier(node)
        {
            return;
        }
        let Some(receiver) = self.enclosing_receiver(node.start_byte()) else {
            return;
        };
        // A bare method-name reference resolves against the enclosing (implicit
        // self) receiver — a same-owner site (#1138).
        self.record_unique_method_candidate(receiver, name, node, MethodLookup::Bare, true);
    }

    fn record_unique_method_candidate(
        &mut self,
        receiver: ReceiverType,
        member: &str,
        node: Node<'_>,
        lookup: MethodLookup,
        same_owner: bool,
    ) {
        // A `self.`/implicit-self call is a same-owner reference (#1138): record
        // it as unproven inbound rather than a proven edge, so a method reachable
        // only through same-owner calls reads INCONCLUSIVE, never confidently
        // dead. An explicit variable/constant receiver — even of the same type —
        // is a different instance and stays external.
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
        self.record_candidates(candidates, member, node, same_owner);
    }

    fn record_candidates(
        &mut self,
        candidates: Vec<CodeUnit>,
        member: &str,
        node: Node<'_>,
        same_owner: bool,
    ) {
        if same_owner {
            self.scan.evidence.record_unproven_name(member, node);
            return;
        }
        if let Some(fqn) = unique_candidate_fqn(candidates) {
            self.scan.evidence.record(fqn, node);
        } else {
            self.scan.evidence.record_unproven_name(member, node);
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
            self.scan.evidence.source,
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
            self.scan.evidence.source,
        );
    }

    fn seed_parameter_shadows(&mut self, node: Node<'_>) {
        ruby_seed_parameter_shadows(&mut self.locals, node, self.scan.evidence.source);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RubyKnowledge;
    use crate::declarations::parse_ruby_tree;
    use brokk_bifrost_core::analyzer::model::CodeUnitType;
    use brokk_bifrost_core::analyzer::usages::inverted_edges::{
        FileDeclarations, FileEdgeSyntax, terminal_index,
    };
    use brokk_bifrost_core::hash::HashMap;
    use brokk_bifrost_core::text_utils::compute_line_starts;

    #[test]
    fn ruby_edge_evidence_preserves_grammar_token_ranges() {
        // Offsets come from Ruby/Ripper's method, constant and symbol tokens.
        let source = "def fixture\n  receiver.run\n  unknown.run\n  self.run\n  Outer::Target\n  obj.__send__(:run)\nend\n";
        let tree = parse_ruby_tree(source).expect("Ruby grammar");
        assert!(!tree.root_node().has_error());
        let method = tree.root_node().named_child(0).expect("method");
        assert_eq!(method.kind(), "method");
        let body = method.child_by_field_name("body").expect("body");
        let mut cursor = body.walk();
        let statements: Vec<_> = body.named_children(&mut cursor).collect();
        assert_eq!(statements.len(), 5);
        let lines = compute_line_starts(source);
        let nodes: HashSet<_> = [
            "fixture".to_string(),
            "Target.run".to_string(),
            "Outer$Target".to_string(),
        ]
        .into_iter()
        .collect();
        let declarations = FileDeclarations {
            enclosers: vec![(
                method.start_byte(),
                method.end_byte(),
                "fixture".to_string(),
            )],
            enclosing_units: HashMap::default(),
            definitions: HashMap::default(),
        };
        let syntax = || FileEdgeSyntax {
            tree: &tree,
            source,
            line_starts: &lines,
        };
        let catalog = terminal_index(&RubyKnowledge, &nodes, |_| vec![CodeUnitType::Function]);
        let input = FileEdgeScanInput::new(
            syntax(),
            &RubyKnowledge,
            Some(&nodes),
            Some(&nodes),
            &declarations,
            &catalog,
        );
        let mut evidence = RubyEdgeEvidence {
            source,
            input: &input,
            edges: PerFileEdges::default(),
        };
        for (index, start) in [(0, 23), (1, 37), (2, 48)] {
            let call = statements[index];
            assert_eq!(call.kind(), "call");
            let token = call.child_by_field_name("method").expect("selector");
            assert_eq!(token.kind(), "identifier");
            assert_eq!(token.byte_range(), start..start + 3);
            if index == 0 {
                evidence.record("Target.run".to_string(), token);
            } else {
                evidence.record_unproven_name("run", token);
            }
        }
        let constant = statements[3];
        assert_eq!(constant.kind(), "scope_resolution");
        assert_eq!(constant.byte_range(), 54..67);
        assert_eq!(
            constant
                .child_by_field_name("name")
                .expect("terminal constant")
                .byte_range(),
            61..67
        );
        evidence.record("Outer$Target".to_string(), constant);
        let symbol = statements[4]
            .child_by_field_name("arguments")
            .expect("dispatch arguments")
            .named_child(0)
            .expect("symbol");
        assert_eq!(symbol.kind(), "simple_symbol");
        assert_eq!(symbol.byte_range(), 83..87);
        evidence.record_unproven_name("run", symbol);
        let selector = statements[4].child_by_field_name("method").unwrap();
        let mut graph_evidence = RubyEdgeEvidence {
            source,
            input: &input,
            edges: PerFileEdges::default(),
        };
        graph_evidence.record_unproven_dispatch(selector);
        assert!(graph_evidence.edges.unproven_inbound.is_empty());
        let callees: HashSet<String> = ["Target.run".to_string()].into_iter().collect();
        let inbound_catalog =
            terminal_index(&RubyKnowledge, &callees, |_| vec![CodeUnitType::Function]);
        let inbound = FileEdgeScanInput::new(
            syntax(),
            &RubyKnowledge,
            None,
            Some(&callees),
            &declarations,
            &inbound_catalog,
        );
        let mut inbound_evidence = RubyEdgeEvidence {
            source,
            input: &inbound,
            edges: PerFileEdges::default(),
        };
        inbound_evidence.record_unproven_dispatch(selector);
        assert_eq!(
            inbound_evidence.edges.unproven_inbound,
            std::collections::BTreeMap::from([(
                "Target.run".to_string(),
                [selector.start_byte()].into_iter().collect::<HashSet<_>>()
            )])
        );
        assert_eq!(
            evidence.edges.edge_lines[&("fixture".to_string(), "Target.run".to_string())][&2].spans,
            [(23, 26)]
        );
        assert_eq!(
            evidence.edges.edge_lines[&("fixture".to_string(), "Outer$Target".to_string())][&5]
                .spans,
            [(54, 67)]
        );
        assert_eq!(
            evidence.edges.unproven_inbound,
            std::collections::BTreeMap::from([(
                "Target.run".to_string(),
                [37, 48, 84].into_iter().collect::<HashSet<_>>()
            )])
        );
    }
}
