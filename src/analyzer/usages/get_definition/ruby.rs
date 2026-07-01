use super::*;
use crate::analyzer::ruby::{RubyFieldScope, ruby_field_short_name};

pub(super) fn resolve_ruby(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(ruby) = resolve_analyzer::<RubyAnalyzer>(analyzer) else {
        return no_definition("ruby_analyzer_unavailable", "Ruby analyzer is unavailable");
    };
    let Some(tree) = tree else {
        return no_definition("ruby_parse_failed", "Ruby source could not be parsed");
    };
    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Ruby definition",
                site.text
            ),
        );
    };

    let semantic = RubySemanticIndex::build_for_lookup(analyzer, ruby);
    let visible_files = semantic.visible_files_from(file);
    let context = RubyLookupContext::build(
        analyzer,
        &semantic,
        file,
        source,
        &visible_files,
        root,
        site.focus_start_byte,
    );

    match ruby_reference_node(node) {
        Some(RubyReferenceNode::Constant(constant)) => {
            if ruby_is_declaration_constant(constant) {
                return no_definition(
                    "declaration_or_import_site",
                    format!("`{}` is not a Ruby reference site", site.text),
                );
            }
            ruby_constant_outcome(&semantic, file, &visible_files, &context, constant, source)
        }
        Some(RubyReferenceNode::Method { call, method }) => ruby_method_outcome(
            support,
            &semantic,
            &visible_files,
            &context,
            call,
            method,
            source,
        ),
        Some(RubyReferenceNode::Identifier(identifier)) => {
            if ruby_is_declaration_identifier(identifier) {
                return no_definition(
                    "declaration_or_import_site",
                    format!("`{}` is not a Ruby reference site", site.text),
                );
            }
            if context
                .locals
                .is_shadowed(ruby_node_text(identifier, source))
            {
                return no_definition(
                    "local_variable_reference",
                    format!("`{}` is a local Ruby value", site.text),
                );
            }
            ruby_method_outcome(
                support,
                &semantic,
                &visible_files,
                &context,
                None,
                identifier,
                source,
            )
        }
        Some(RubyReferenceNode::Variable(variable)) => {
            ruby_field_outcome(analyzer, support, &semantic, &context, variable, source)
        }
        None => no_definition(
            "unsupported_ruby_reference_shape",
            format!(
                "`{}` is a Ruby `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

enum RubyReferenceNode<'tree> {
    Constant(Node<'tree>),
    Method {
        call: Option<Node<'tree>>,
        method: Node<'tree>,
    },
    Identifier(Node<'tree>),
    Variable(Node<'tree>),
}

fn ruby_reference_node(node: Node<'_>) -> Option<RubyReferenceNode<'_>> {
    match node.kind() {
        "constant" => Some(RubyReferenceNode::Constant(ruby_focused_constant_path(
            node,
        ))),
        "scope_resolution" => Some(RubyReferenceNode::Constant(node)),
        "instance_variable" | "class_variable" => Some(RubyReferenceNode::Variable(node)),
        "identifier" => {
            if ruby_is_call_method_identifier(node) {
                return Some(RubyReferenceNode::Method {
                    call: node.parent(),
                    method: node,
                });
            }
            Some(RubyReferenceNode::Identifier(node))
        }
        "call" => node
            .child_by_field_name("method")
            .map(|method| RubyReferenceNode::Method {
                call: Some(node),
                method,
            }),
        _ => {
            let parent = node.parent()?;
            match parent.kind() {
                "call" if parent.child_by_field_name("method") == Some(node) => {
                    Some(RubyReferenceNode::Method {
                        call: Some(parent),
                        method: node,
                    })
                }
                _ => None,
            }
        }
    }
}

/// Resolve a constant path *up to and including* the focused segment: clicking
/// `Foo` in `Foo::Bar::Baz` targets `Foo`, `Bar` targets `Foo::Bar`, and `Baz`
/// targets the whole path. tree-sitter nests `scope_resolution` to the left, so a
/// segment's enclosing path is its parent `scope_resolution` exactly when the
/// segment is that node's terminal `name` (a left `scope` segment resolves to just
/// the constant). This also covers assignment-LHS chains, whose leftmost scope
/// segment naturally resolves to itself.
fn ruby_focused_constant_path(node: Node<'_>) -> Node<'_> {
    if let Some(parent) = node.parent()
        && parent.kind() == "scope_resolution"
        && parent.child_by_field_name("name") == Some(node)
    {
        parent
    } else {
        node
    }
}

fn ruby_constant_outcome(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    context: &RubyLookupContext,
    node: Node<'_>,
    source: &str,
) -> DefinitionLookupOutcome {
    let raw = ruby_node_text(node, source);
    let Some(unit) =
        semantic.resolve_constant(file, visible_files, &context.lexical_stack, node, source)
    else {
        return no_definition(
            "no_indexed_definition",
            format!("`{raw}` did not resolve to an indexed Ruby definition"),
        );
    };
    candidates_outcome(vec![unit])
}

fn ruby_field_outcome(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    semantic: &RubySemanticIndex<'_>,
    context: &RubyLookupContext,
    node: Node<'_>,
    source: &str,
) -> DefinitionLookupOutcome {
    let raw = ruby_node_text(node, source);
    let Some((owner, scope)) =
        ruby_field_reference_owner_and_scope(&context.lexical_stack, &context.method_stack, node)
    else {
        return no_definition(
            "unsupported_ruby_receiver",
            format!("receiver for Ruby field `{raw}` is not resolved"),
        );
    };

    let owners: Vec<String> = match scope {
        RubyFieldScope::ClassVariable => std::iter::once(owner.clone())
            .chain(semantic.ancestor_lookup_order(&owner))
            .collect(),
        RubyFieldScope::Instance | RubyFieldScope::SingletonClass => vec![owner],
    };

    let mut candidates = Vec::new();
    for owner in owners {
        let segments: Vec<String> = owner
            .split('$')
            .filter(|segment| !segment.is_empty())
            .map(str::to_string)
            .collect();
        if let Some(fqn) = ruby_field_short_name(&segments, node, source, scope) {
            candidates.extend(support.fqn(&fqn));
        }
    }
    candidates.retain(|unit| {
        unit.is_field()
            && unit.identifier() == raw
            && context.visible_files.contains(unit.source())
            && ruby_field_target_from_code_unit(unit).is_some_and(|target| target.scope == scope)
    });
    sort_units(&mut candidates);
    candidates.dedup();

    if candidates
        .iter()
        .any(|candidate| ruby_is_indexed_field_declaration_site(analyzer, candidate, node))
    {
        return no_definition(
            "declaration_or_import_site",
            format!("`{raw}` is not a Ruby reference site"),
        );
    }

    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("Ruby field `{raw}` did not resolve to an indexed definition"),
        );
    }
    candidates_outcome(candidates)
}

fn ruby_is_indexed_field_declaration_site(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    node: Node<'_>,
) -> bool {
    if !ruby_is_plain_assignment_left_variable(node) {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    analyzer
        .ranges(target)
        .iter()
        .any(|range| range.start_byte == parent.start_byte() && range.end_byte == parent.end_byte())
}

fn ruby_method_outcome(
    support: &DefinitionLookupIndex,
    semantic: &RubySemanticIndex<'_>,
    visible_files: &HashSet<ProjectFile>,
    context: &RubyLookupContext,
    call: Option<Node<'_>>,
    method: Node<'_>,
    source: &str,
) -> DefinitionLookupOutcome {
    if call.is_some_and(|call| ruby_is_dynamic_dispatch(call, source)) {
        return no_definition(
            "unsupported_ruby_dynamic_dispatch",
            "Ruby dynamic dispatch is not resolved by get_definition",
        );
    }

    let member = ruby_node_text(method, source);
    if member.is_empty() {
        return no_definition("no_reference_text", "Ruby method reference is blank");
    }

    let receiver = match call.and_then(|call| call.child_by_field_name("receiver")) {
        Some(receiver) => context.receiver_type(receiver),
        None => context.enclosing_receiver(),
    };
    let Some(receiver) = receiver else {
        return no_definition(
            "unsupported_ruby_receiver",
            format!("receiver for Ruby method `{member}` is not resolved"),
        );
    };

    let candidates = if call
        .and_then(|call| call.child_by_field_name("receiver"))
        .is_none()
    {
        semantic.resolve_bare_method_candidates(support, visible_files, &receiver, member)
    } else {
        semantic.resolve_method_candidates(support, visible_files, &receiver, member)
    };

    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("Ruby method `{member}` did not resolve to an indexed definition"),
        );
    }
    candidates_outcome(candidates)
}

struct RubyLookupContext<'a> {
    semantic: &'a RubySemanticIndex<'a>,
    file: &'a ProjectFile,
    source: &'a str,
    visible_files: &'a HashSet<ProjectFile>,
    locals: LocalInferenceEngine<String>,
    lexical_stack: Vec<String>,
    method_stack: Vec<RubyReceiverMode>,
    exits: Vec<RubyExit>,
    focus_start: usize,
}

impl<'a> RubyLookupContext<'a> {
    fn build(
        _analyzer: &'a dyn IAnalyzer,
        semantic: &'a RubySemanticIndex<'a>,
        file: &'a ProjectFile,
        source: &'a str,
        visible_files: &'a HashSet<ProjectFile>,
        root: Node<'_>,
        focus_start: usize,
    ) -> Self {
        let mut context = Self {
            semantic,
            file,
            source,
            visible_files,
            locals: LocalInferenceEngine::new(LocalInferenceConfig::default()),
            lexical_stack: Vec::new(),
            method_stack: Vec::new(),
            exits: Vec::new(),
            focus_start,
        };
        context.walk_to_focus(root);
        context
    }

    fn walk_to_focus(&mut self, root: Node<'_>) {
        let mut stack = vec![RubyFrame::Enter(root)];
        let mut reached_focus = false;
        while let Some(frame) = stack.pop() {
            if reached_focus {
                break;
            }
            match frame {
                RubyFrame::Enter(node) => match self.enter(node) {
                    RubyWalkAction::Descend => {
                        for index in (0..node.named_child_count()).rev() {
                            if let Some(child) = node.named_child(index) {
                                stack.push(RubyFrame::Enter(child));
                            }
                        }
                    }
                    RubyWalkAction::DescendWithExit => {
                        stack.push(RubyFrame::Exit);
                        for index in (0..node.named_child_count()).rev() {
                            if let Some(child) = node.named_child(index) {
                                stack.push(RubyFrame::Enter(child));
                            }
                        }
                    }
                    RubyWalkAction::Skip => {
                        reached_focus = node.start_byte() >= self.focus_start;
                    }
                },
                RubyFrame::Exit => self.exit(),
            }
        }
    }

    fn enter(&mut self, node: Node<'_>) -> RubyWalkAction {
        if node.start_byte() >= self.focus_start {
            return RubyWalkAction::Skip;
        }
        if node.end_byte() <= self.focus_start {
            if node.kind() == "assignment" {
                self.seed_assignment(node);
            }
            return RubyWalkAction::Skip;
        }

        match node.kind() {
            "class" | "module" => {
                if let Some(owner) = self.type_owner(node) {
                    self.lexical_stack.push(owner);
                    self.exits.push(RubyExit::Lexical);
                    return RubyWalkAction::DescendWithExit;
                }
            }
            "method" | "singleton_method" => {
                self.locals.enter_scope();
                self.seed_parameter_shadows(node);
                self.method_stack.push(ruby_method_receiver_mode(node));
                self.exits.push(RubyExit::Method);
                return RubyWalkAction::DescendWithExit;
            }
            "singleton_class" => {
                self.locals.enter_scope();
                self.method_stack.push(RubyReceiverMode::Class);
                self.exits.push(RubyExit::Method);
                return RubyWalkAction::DescendWithExit;
            }
            "block" | "do_block" => {
                self.locals.enter_scope();
                self.exits.push(RubyExit::LocalScope);
                return RubyWalkAction::DescendWithExit;
            }
            "assignment" => self.seed_assignment(node),
            _ => {}
        }
        RubyWalkAction::Descend
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
            self.semantic,
            self.file,
            self.visible_files,
            &self.lexical_stack,
            node,
            self.source,
        )
    }

    fn receiver_type(&self, node: Node<'_>) -> Option<RubyReceiverType> {
        ruby_receiver_type(
            self.semantic,
            self.file,
            self.visible_files,
            &self.lexical_stack,
            &self.locals,
            &self.method_stack,
            node,
            self.source,
        )
    }

    fn enclosing_receiver(&self) -> Option<RubyReceiverType> {
        ruby_enclosing_receiver(&self.lexical_stack, &self.method_stack)
    }

    fn seed_assignment(&mut self, node: Node<'_>) {
        ruby_seed_assignment(
            self.semantic,
            self.file,
            self.visible_files,
            &self.lexical_stack,
            &self.method_stack,
            &mut self.locals,
            node,
            self.source,
        );
    }

    fn seed_parameter_shadows(&mut self, node: Node<'_>) {
        ruby_seed_parameter_shadows(&mut self.locals, node, self.source);
    }
}

enum RubyFrame<'tree> {
    Enter(Node<'tree>),
    Exit,
}

enum RubyWalkAction {
    Descend,
    DescendWithExit,
    Skip,
}

enum RubyExit {
    Lexical,
    Method,
    LocalScope,
}

fn ruby_is_dynamic_dispatch(call: Node<'_>, source: &str) -> bool {
    let Some(method) = call.child_by_field_name("method") else {
        return false;
    };
    if !ruby_is_dynamic_dispatch_method(method, source) {
        return false;
    }
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .any(|arg| ruby_symbol_or_string_value(arg, source).is_some())
}
