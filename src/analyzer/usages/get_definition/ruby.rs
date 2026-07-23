use super::*;
use crate::analyzer::BoundedDefinitionLookup;
use crate::analyzer::RubyMethodDispatchMode;
use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner_bounded;
use crate::analyzer::ruby::{RubyFieldScope, RubyNamePath, ruby_field_short_name};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;

pub(crate) struct RubyDefinitionProvider<'a> {
    ruby: &'a RubyAnalyzer,
    session: &'a ResolutionSession,
}

impl<'a> RubyDefinitionProvider<'a> {
    pub(crate) fn new(ruby: &'a RubyAnalyzer, session: &'a ResolutionSession) -> Self {
        Self { ruby, session }
    }

    pub(crate) fn members_for_owner_name(&self, owner_fqn: &str, name: &str) -> Vec<CodeUnit> {
        let mut units = self.session.query_limited_rows(|limit| {
            self.ruby
                .member_candidates_for_owner_limited(owner_fqn, name, limit, || {
                    self.session.observe_cancellation()
                })
        });
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn ranges(&self, unit: &CodeUnit) -> Vec<Range> {
        self.session
            .query_limited_rows(|limit| self.ruby.ranges_limited(unit, limit))
    }

    fn parent(&self, unit: &CodeUnit) -> Option<CodeUnit> {
        if !self.scope_step() {
            return None;
        }
        let fq_name = unit.fq_name();
        let owner_fqn = fq_name.strip_suffix(unit.identifier())?.strip_suffix('.')?;
        if owner_fqn.is_empty() {
            return None;
        }
        let mut owners = self
            .fqn(owner_fqn)
            .into_iter()
            .filter(|owner| owner.is_class() || owner.is_module())
            .collect::<Vec<_>>();
        sort_units(&mut owners);
        owners.dedup();
        let [owner] = owners.as_slice() else {
            return None;
        };
        self.members_for_owner_name(owner_fqn, unit.identifier())
            .iter()
            .any(|candidate| candidate == unit)
            .then(|| owner.clone())
    }

    fn method_dispatch_mode(&self, unit: &CodeUnit) -> Option<RubyMethodDispatchMode> {
        let modes = self
            .session
            .query_limited_rows(|limit| self.ruby.method_dispatch_modes_limited(unit, limit));
        let [mode] = modes.as_slice() else {
            return None;
        };
        Some(*mode)
    }

    fn scope_step(&self) -> bool {
        self.session.scope_step()
    }
}

impl BoundedDefinitionLookup for RubyDefinitionProvider<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut units = self.session.query_limited_rows(|limit| {
            self.ruby
                .declaration_candidates_by_fqn_limited(fqn, limit, || {
                    self.session.observe_cancellation()
                })
        });
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        if language == Language::Ruby {
            self.fqn(fqn)
        } else {
            self.session.mark_scope_incomplete();
            Vec::new()
        }
    }

    fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        let mut units = self
            .session
            .query_limited_rows(|limit| {
                self.ruby
                    .declaration_candidates_by_identifier_limited(ident, limit, || {
                        self.session.observe_cancellation()
                    })
            })
            .into_iter()
            .filter(|unit| unit.source() == file)
            .collect::<Vec<_>>();
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut children = Vec::new();
        for owner in self.fqn(fqn) {
            children.extend(
                self.session
                    .query_limited_rows(|limit| self.ruby.direct_children_limited(&owner, limit)),
            );
            if !self.session.observe_cancellation() {
                return Vec::new();
            }
        }
        sort_units(&mut children);
        children.dedup();
        children
    }

    fn fqn_exists(&self, fqn: &str) -> bool {
        !self.fqn(fqn).is_empty()
    }

    fn package_exists(&self, _package: &str) -> bool {
        false
    }

    fn package_exists_in_language(&self, _package: &str, language: Language) -> bool {
        if language != Language::Ruby {
            self.session.mark_scope_incomplete();
        }
        false
    }

    fn fqn_prefix_exists(&self, _prefix: &str) -> bool {
        false
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RubyTypeLookupResolution {
    pub(crate) fqn: String,
    pub(crate) target_kind: TypeLookupTargetKind,
}

pub(crate) fn resolve_ruby_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(ruby) = resolve_analyzer::<RubyAnalyzer>(analyzer) else {
        return session.finish(no_definition(
            "ruby_analyzer_unavailable",
            "Ruby analyzer is unavailable",
        ));
    };
    let Some(tree) = tree else {
        return session.finish(no_definition(
            "ruby_parse_failed",
            "Ruby source could not be parsed",
        ));
    };
    let provider = RubyDefinitionProvider::new(ruby, &session);
    let outcome = resolve_ruby_bounded_in_session(&provider, file, source, tree.root_node(), site);
    session.finish(outcome)
}

fn resolve_ruby_bounded_in_session(
    provider: &RubyDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(node) = ruby_smallest_named_node_covering_bounded(
        provider,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    ) else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Ruby definition",
                site.text
            ),
        );
    };
    match ruby_reference_node(node, source) {
        Some(RubyReferenceNode::Constant(constant)) => {
            if ruby_is_declaration_constant(constant) {
                return no_definition(
                    "declaration_or_import_site",
                    format!("`{}` is not a Ruby reference site", site.text),
                );
            }
            let context = BoundedRubyLookupContext::build(
                provider,
                file,
                source,
                root,
                site.focus_start_byte,
            );
            let Some(receiver) = context.constant_receiver_type(constant) else {
                return no_definition(
                    "no_indexed_definition",
                    format!(
                        "`{}` did not resolve to an exact indexed Ruby constant",
                        site.text
                    ),
                );
            };
            candidates_outcome(provider.fqn(&receiver.owner_fq_name))
        }
        Some(RubyReferenceNode::Method { call, method }) => {
            let context = BoundedRubyLookupContext::build(
                provider,
                file,
                source,
                root,
                site.focus_start_byte,
            );
            ruby_bounded_method_outcome(provider, &context, call, method, source)
        }
        Some(RubyReferenceNode::Identifier(identifier)) => {
            if ruby_is_declaration_identifier(identifier) {
                return no_definition(
                    "declaration_or_import_site",
                    format!("`{}` is not a Ruby reference site", site.text),
                );
            }
            let context = BoundedRubyLookupContext::build(
                provider,
                file,
                source,
                root,
                site.focus_start_byte,
            );
            if context
                .local_receiver_type(ruby_node_text(identifier, source))
                .is_some()
            {
                return no_definition(
                    "local_variable_reference",
                    format!("`{}` is a local Ruby value", site.text),
                );
            }
            ruby_bounded_method_outcome(provider, &context, None, identifier, source)
        }
        Some(RubyReferenceNode::AutoloadSymbol(_)) => no_definition(
            "ruby_autoload_scope_unproven",
            "bounded Ruby lookup does not expand project-wide autoload conventions",
        ),
        Some(RubyReferenceNode::Variable(_)) => no_definition(
            "unsupported_ruby_receiver",
            "bounded Ruby field lookup requires heap/member refinement",
        ),
        None => no_definition(
            "unsupported_ruby_reference_shape",
            format!(
                "`{}` is a Ruby `{}` reference shape that bounded get_definition does not resolve",
                site.text,
                node.kind()
            ),
        ),
    }
}

pub(crate) fn ruby_type_lookup_resolution_bounded(
    provider: &RubyDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<RubyTypeLookupResolution> {
    let node = ruby_smallest_named_node_covering_bounded(
        provider,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
    let context =
        BoundedRubyLookupContext::build(provider, file, source, root, site.focus_start_byte);
    let receiver = context.expression_receiver_type(node)?;
    let target_kind = if receiver.mode == RubyReceiverMode::Class
        && matches!(node.kind(), "constant" | "scope_resolution")
    {
        TypeLookupTargetKind::TypeReference
    } else {
        TypeLookupTargetKind::ValueExpression
    };
    Some(RubyTypeLookupResolution {
        fqn: receiver.owner_fq_name,
        target_kind,
    })
}

fn ruby_bounded_method_outcome(
    provider: &RubyDefinitionProvider<'_>,
    context: &BoundedRubyLookupContext<'_, '_>,
    call: Option<Node<'_>>,
    method: Node<'_>,
    source: &str,
) -> DefinitionLookupOutcome {
    if call.is_some_and(|call| ruby_is_dynamic_dispatch(call, source)) {
        return no_definition(
            "unsupported_ruby_dynamic_dispatch",
            "Ruby send/public_send dispatch remains explicitly unsupported",
        );
    }
    let member = ruby_node_text(method, source);
    if member.is_empty() {
        return no_definition("no_reference_text", "Ruby method reference is blank");
    }
    let receiver = match call.and_then(|call| call.child_by_field_name("receiver")) {
        Some(receiver) => context.expression_receiver_type(receiver),
        None => context.enclosing_receiver(),
    };
    let Some(receiver) = receiver else {
        return no_definition(
            "unsupported_ruby_receiver",
            format!("receiver for Ruby method `{member}` is not structurally resolved"),
        );
    };
    let mut candidates = provider
        .members_for_owner_name(&receiver.owner_fq_name, member)
        .into_iter()
        .filter(|unit| {
            unit.is_function()
                && provider
                    .method_dispatch_mode(unit)
                    .is_some_and(|mode| ruby_dispatch_mode_matches(mode, receiver.mode))
        })
        .collect::<Vec<_>>();
    sort_units(&mut candidates);
    candidates.dedup();
    if candidates.is_empty() {
        return no_definition(
            "ruby_inherited_or_dynamic_dispatch_unproven",
            format!(
                "Ruby method `{member}` has no exact direct declaration on `{}`; mixins, inheritance, refinements, monkeypatching, and method_missing remain open",
                receiver.owner_fq_name
            ),
        );
    }
    candidates_outcome(candidates)
}

fn ruby_dispatch_mode_matches(
    declaration: RubyMethodDispatchMode,
    receiver: RubyReceiverMode,
) -> bool {
    matches!(
        (declaration, receiver),
        (
            RubyMethodDispatchMode::Instance,
            RubyReceiverMode::Instance | RubyReceiverMode::TopLevel
        ) | (RubyMethodDispatchMode::Singleton, RubyReceiverMode::Class)
            | (RubyMethodDispatchMode::ModuleFunction, _)
    )
}

struct BoundedRubyLookupContext<'a, 'tree> {
    provider: &'a RubyDefinitionProvider<'a>,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'tree>,
    lexical_stack: Vec<String>,
    method_stack: Vec<RubyReceiverMode>,
    local_scopes: Vec<HashMap<Box<str>, Option<RubyReceiverType>>>,
    exits: Vec<BoundedRubyExit>,
    focus_start: usize,
}

impl<'a, 'tree> BoundedRubyLookupContext<'a, 'tree> {
    fn build(
        provider: &'a RubyDefinitionProvider<'a>,
        file: &'a ProjectFile,
        source: &'a str,
        root: Node<'tree>,
        focus_start: usize,
    ) -> Self {
        let mut context = Self {
            provider,
            file,
            source,
            root,
            lexical_stack: Vec::new(),
            method_stack: Vec::new(),
            local_scopes: vec![HashMap::default()],
            exits: Vec::new(),
            focus_start,
        };
        context.walk_to_focus(root);
        context
    }

    fn walk_to_focus(&mut self, root: Node<'_>) {
        let mut stack = vec![BoundedRubyFrame::Enter(root)];
        let mut reached_focus = false;
        while let Some(frame) = stack.pop() {
            if reached_focus || !self.provider.scope_step() {
                break;
            }
            match frame {
                BoundedRubyFrame::Enter(node) => match self.enter(node) {
                    BoundedRubyWalkAction::Descend => {
                        stack.push(BoundedRubyFrame::NextChild { node, index: 0 });
                    }
                    BoundedRubyWalkAction::DescendWithExit => {
                        stack.push(BoundedRubyFrame::Exit);
                        stack.push(BoundedRubyFrame::NextChild { node, index: 0 });
                    }
                    BoundedRubyWalkAction::Skip => {
                        reached_focus = node.start_byte() >= self.focus_start;
                    }
                },
                BoundedRubyFrame::NextChild { node, index } => {
                    if index < node.named_child_count() {
                        stack.push(BoundedRubyFrame::NextChild {
                            node,
                            index: index + 1,
                        });
                        if let Some(child) = node.named_child(index) {
                            stack.push(BoundedRubyFrame::Enter(child));
                        }
                    }
                }
                BoundedRubyFrame::Exit => self.exit(),
            }
        }
    }

    fn enter(&mut self, node: Node<'_>) -> BoundedRubyWalkAction {
        if node.start_byte() >= self.focus_start {
            return BoundedRubyWalkAction::Skip;
        }
        if node.end_byte() <= self.focus_start {
            if node.kind() == "assignment" {
                self.seed_assignment(node);
            }
            return BoundedRubyWalkAction::Skip;
        }
        match node.kind() {
            "class" | "module" => {
                let Some(name) = node.child_by_field_name("name") else {
                    return BoundedRubyWalkAction::Descend;
                };
                if let Some(owner) = self.resolve_constant_owner(name) {
                    self.lexical_stack.push(owner);
                    self.exits.push(BoundedRubyExit::Lexical);
                    return BoundedRubyWalkAction::DescendWithExit;
                }
            }
            "method" | "singleton_method" => {
                self.method_stack.push(ruby_method_receiver_mode(node));
                self.local_scopes.push(HashMap::default());
                self.seed_parameter_shadows(node);
                self.exits.push(BoundedRubyExit::Method);
                return BoundedRubyWalkAction::DescendWithExit;
            }
            "singleton_class" => {
                self.method_stack.push(RubyReceiverMode::Class);
                self.local_scopes.push(HashMap::default());
                self.exits.push(BoundedRubyExit::Method);
                return BoundedRubyWalkAction::DescendWithExit;
            }
            "block" | "do_block" => {
                let inherited = self.local_scopes.last().cloned().unwrap_or_default();
                self.local_scopes.push(inherited);
                self.seed_parameter_shadows(node);
                self.exits.push(BoundedRubyExit::LocalScope);
                return BoundedRubyWalkAction::DescendWithExit;
            }
            "assignment" => self.seed_assignment(node),
            _ => {}
        }
        BoundedRubyWalkAction::Descend
    }

    fn exit(&mut self) {
        match self.exits.pop() {
            Some(BoundedRubyExit::Lexical) => {
                self.lexical_stack.pop();
            }
            Some(BoundedRubyExit::Method) => {
                self.method_stack.pop();
                self.local_scopes.pop();
            }
            Some(BoundedRubyExit::LocalScope) => {
                self.local_scopes.pop();
            }
            None => {}
        }
    }

    fn seed_parameter_shadows(&mut self, callable: Node<'_>) {
        let provider = self.provider;
        let layout = formal_parameter_slots_for_owner_bounded(
            Language::Ruby,
            callable,
            self.source,
            &ruby_node_range(callable),
            || provider.scope_step(),
        )
        .unwrap_or_default();
        let Some(locals) = self.local_scopes.last_mut() else {
            return;
        };
        for slot in layout.slots {
            for name in slot.names {
                locals.insert(name.into_boxed_str(), None);
            }
        }
    }

    fn seed_assignment(&mut self, node: Node<'_>) {
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        if left.kind() != "identifier" {
            return;
        }
        let name = ruby_node_text(left, self.source);
        if name.is_empty() {
            return;
        }
        let value = node
            .child_by_field_name("right")
            .and_then(|right| self.expression_receiver_type(right));
        if let Some(locals) = self.local_scopes.last_mut() {
            locals.insert(name.into(), value);
        }
    }

    fn local_receiver_type(&self, name: &str) -> Option<RubyReceiverType> {
        self.local_scopes
            .last()
            .and_then(|locals| locals.get(name))
            .cloned()
            .flatten()
    }

    fn enclosing_receiver(&self) -> Option<RubyReceiverType> {
        let owner_fq_name = self.lexical_stack.last()?.clone();
        let mode = self
            .method_stack
            .last()
            .copied()
            .unwrap_or(RubyReceiverMode::Class);
        Some(RubyReceiverType {
            owner_fq_name,
            mode,
        })
    }

    fn constant_receiver_type(&self, node: Node<'_>) -> Option<RubyReceiverType> {
        self.resolve_constant_owner(node)
            .map(|owner_fq_name| RubyReceiverType {
                owner_fq_name,
                mode: RubyReceiverMode::Class,
            })
    }

    fn expression_receiver_type(&self, node: Node<'_>) -> Option<RubyReceiverType> {
        self.expression_receiver_type_at_depth(node, 0)
    }

    fn expression_receiver_type_at_depth(
        &self,
        mut node: Node<'_>,
        depth: usize,
    ) -> Option<RubyReceiverType> {
        if depth >= 12 || !self.provider.scope_step() {
            return None;
        }
        while matches!(node.kind(), "parenthesized_statements") {
            if !self.provider.scope_step() {
                return None;
            }
            node = ruby_first_named_child(node)?;
        }
        match node.kind() {
            "constant" | "scope_resolution" => self.constant_receiver_type(node),
            "self" => self.enclosing_receiver(),
            "identifier" => self.local_receiver_type(ruby_node_text(node, self.source)),
            "call" => self.call_result_receiver_type(node, depth + 1),
            _ => None,
        }
    }

    fn call_result_receiver_type(&self, call: Node<'_>, depth: usize) -> Option<RubyReceiverType> {
        if depth >= 12 || !self.provider.scope_step() {
            return None;
        }
        let method = call.child_by_field_name("method")?;
        let method_name = ruby_node_text(method, self.source);
        if method_name.is_empty() || matches!(method_name, "send" | "public_send") {
            return None;
        }
        let receiver = match call.child_by_field_name("receiver") {
            Some(receiver) => self.expression_receiver_type_at_depth(receiver, depth + 1)?,
            None => self.enclosing_receiver()?,
        };
        if method_name == "new" {
            return (receiver.mode == RubyReceiverMode::Class).then_some(RubyReceiverType {
                owner_fq_name: receiver.owner_fq_name,
                mode: RubyReceiverMode::Instance,
            });
        }
        let mut candidates = self
            .provider
            .members_for_owner_name(&receiver.owner_fq_name, method_name)
            .into_iter()
            .filter(|unit| {
                unit.is_function()
                    && self
                        .provider
                        .method_dispatch_mode(unit)
                        .is_some_and(|mode| ruby_dispatch_mode_matches(mode, receiver.mode))
            })
            .collect::<Vec<_>>();
        sort_units(&mut candidates);
        candidates.dedup();
        let method = (candidates.len() == 1).then(|| candidates.remove(0))?;
        self.factory_method_return_receiver_type(&method, &receiver, depth + 1)
    }

    fn factory_method_return_receiver_type(
        &self,
        method: &CodeUnit,
        invocation_receiver: &RubyReceiverType,
        depth: usize,
    ) -> Option<RubyReceiverType> {
        if depth >= 12 || method.source() != self.file || !self.provider.scope_step() {
            return None;
        }
        let ranges = self.provider.ranges(method);
        let range = (ranges.len() == 1).then(|| ranges[0].clone())?;
        let method_node = self.method_node_for_range(&range)?;
        let mut expression = self.tail_expression(method_node)?;
        if expression.kind() == "assignment" {
            expression = expression.child_by_field_name("right")?;
        } else if expression.kind() == "return" {
            expression = ruby_first_named_child(expression)?;
        }
        if expression.kind() != "call"
            || expression
                .child_by_field_name("method")
                .is_none_or(|name| ruby_node_text(name, self.source) != "new")
        {
            return None;
        }
        let owner_fq_name = match expression.child_by_field_name("receiver") {
            Some(receiver) if receiver.kind() == "self" => {
                if invocation_receiver.mode != RubyReceiverMode::Class {
                    return None;
                }
                invocation_receiver.owner_fq_name.clone()
            }
            Some(receiver) if matches!(receiver.kind(), "constant" | "scope_resolution") => {
                let lexical_owner = self.provider.parent(method).map(|owner| owner.fq_name());
                self.resolve_constant_owner_from(receiver, lexical_owner.as_deref())?
            }
            _ => return None,
        };
        Some(RubyReceiverType {
            owner_fq_name,
            mode: RubyReceiverMode::Instance,
        })
    }

    fn method_node_for_range(&self, range: &Range) -> Option<Node<'tree>> {
        let mut node = self.root;
        loop {
            if !self.provider.scope_step() {
                return None;
            }
            if range.start_byte == node.start_byte()
                && range.end_byte == node.end_byte()
                && matches!(node.kind(), "method" | "singleton_method")
            {
                return Some(node);
            }
            let mut next = None;
            for index in 0..node.named_child_count() {
                if !self.provider.scope_step() {
                    return None;
                }
                let child = node.named_child(index)?;
                if child.start_byte() <= range.start_byte && range.end_byte <= child.end_byte() {
                    next = Some(child);
                    break;
                }
            }
            node = next?;
        }
    }

    fn tail_expression(&self, method: Node<'tree>) -> Option<Node<'tree>> {
        let body = method.child_by_field_name("body")?;
        let mut tail = None;
        for index in 0..body.named_child_count() {
            if !self.provider.scope_step() {
                return None;
            }
            tail = body.named_child(index);
        }
        tail
    }

    fn resolve_constant_owner_from(
        &self,
        node: Node<'_>,
        lexical_owner: Option<&str>,
    ) -> Option<String> {
        let path = self.constant_name_path(node)?;
        if path.segments.is_empty() {
            return None;
        }
        let relative = path.segments.join("$");
        let mut candidates = Vec::new();
        if !path.absolute
            && let Some(owner) = lexical_owner
            && !owner.is_empty()
        {
            candidates.push(format!("{owner}${relative}"));
        }
        candidates.push(relative);
        candidates.into_iter().find(|candidate| {
            let mut matches = self
                .provider
                .fqn(candidate)
                .into_iter()
                .filter(|unit| {
                    unit.fq_name() == *candidate && (unit.is_class() || unit.is_module())
                })
                .collect::<Vec<_>>();
            sort_units(&mut matches);
            matches.dedup();
            matches.len() == 1
        })
    }

    fn resolve_constant_owner(&self, node: Node<'_>) -> Option<String> {
        let path = self.constant_name_path(node)?;
        if path.segments.is_empty() {
            return None;
        }
        let relative = path.segments.join("$");
        let mut candidates = Vec::new();
        if !path.absolute {
            candidates.extend(
                self.lexical_stack
                    .iter()
                    .rev()
                    .map(|owner| format!("{owner}${relative}")),
            );
        }
        candidates.push(relative);
        candidates.into_iter().find(|candidate| {
            self.provider
                .fqn(candidate)
                .into_iter()
                .any(|unit| unit.fq_name() == *candidate && (unit.is_class() || unit.is_module()))
        })
    }

    /// Interpret a Ruby constant path from tree-sitter fields while charging
    /// every visited path node to this bounded lookup. Ruby nests
    /// `scope_resolution` nodes to the left, so an explicit stack preserves
    /// source order without an unmetered recursive descent.
    fn constant_name_path(&self, node: Node<'_>) -> Option<RubyNamePath> {
        let mut stack = vec![node];
        let mut segments = Vec::new();
        let mut absolute = false;
        while let Some(current) = stack.pop() {
            if !self.provider.scope_step() {
                return None;
            }
            match current.kind() {
                "scope_resolution" => {
                    let name = current.child_by_field_name("name")?;
                    stack.push(name);
                    if let Some(scope) = current.child_by_field_name("scope") {
                        stack.push(scope);
                    } else {
                        absolute = true;
                    }
                }
                "constant" => {
                    let segment = ruby_node_text(current, self.source);
                    if segment.is_empty() {
                        return None;
                    }
                    segments.push(segment.to_string());
                }
                _ => return None,
            }
        }
        Some(RubyNamePath { segments, absolute })
    }
}

enum BoundedRubyFrame<'tree> {
    Enter(Node<'tree>),
    NextChild { node: Node<'tree>, index: usize },
    Exit,
}

enum BoundedRubyWalkAction {
    Descend,
    DescendWithExit,
    Skip,
}

enum BoundedRubyExit {
    Lexical,
    Method,
    LocalScope,
}

fn ruby_smallest_named_node_covering_bounded<'tree>(
    provider: &RubyDefinitionProvider<'_>,
    mut node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    if start > end || start < node.start_byte() || end > node.end_byte() {
        return None;
    }
    loop {
        if !provider.scope_step() {
            return None;
        }
        let mut next = None;
        for index in 0..node.named_child_count() {
            if !provider.scope_step() {
                return None;
            }
            let child = node.named_child(index)?;
            if child.start_byte() <= start && end <= child.end_byte() {
                next = Some(child);
                break;
            }
        }
        match next {
            Some(child) => node = child,
            None => return Some(node),
        }
    }
}

fn ruby_node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    }
}

fn ruby_first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

pub(super) fn resolve_ruby(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
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

    match ruby_reference_node(node, source) {
        Some(RubyReferenceNode::Constant(constant)) => {
            if ruby_is_declaration_constant(constant) {
                return no_definition(
                    "declaration_or_import_site",
                    format!("`{}` is not a Ruby reference site", site.text),
                );
            }
            ruby_constant_outcome(&semantic, file, &visible_files, &context, constant, source)
        }
        Some(RubyReferenceNode::AutoloadSymbol(symbol)) => {
            ruby_autoload_symbol_outcome(&semantic, file, &visible_files, &context, symbol, source)
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
    AutoloadSymbol(Node<'tree>),
    Method {
        call: Option<Node<'tree>>,
        method: Node<'tree>,
    },
    Identifier(Node<'tree>),
    Variable(Node<'tree>),
}

fn ruby_reference_node<'tree>(node: Node<'tree>, source: &str) -> Option<RubyReferenceNode<'tree>> {
    match node.kind() {
        "constant" => Some(RubyReferenceNode::Constant(ruby_focused_constant_path(
            node,
        ))),
        "simple_symbol"
            if crate::analyzer::ruby::is_ruby_autoload_symbol_argument(node, source) =>
        {
            Some(RubyReferenceNode::AutoloadSymbol(node))
        }
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

fn ruby_autoload_symbol_outcome(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    context: &RubyLookupContext,
    node: Node<'_>,
    source: &str,
) -> DefinitionLookupOutcome {
    let raw = ruby_node_text(node, source);
    let Some(name) = crate::analyzer::ruby::ruby_symbol_name(node, source) else {
        return no_definition(
            "unsupported_ruby_reference_shape",
            format!("`{raw}` is not a Ruby autoload constant symbol"),
        );
    };
    let Some(unit) =
        semantic.resolve_constant_name(file, visible_files, &context.lexical_stack, &name)
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
    support: &dyn BoundedDefinitionLookup,
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
            .chain(semantic.forward_ancestor_lookup_order(
                support,
                &context.visible_files.iter().cloned().collect::<Vec<_>>(),
                &owner,
            ))
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
    support: &dyn BoundedDefinitionLookup,
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

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use crate::analyzer::ruby::parse_ruby_tree;
    use crate::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    use crate::analyzer::{AnalyzerConfig, Project, TestProject, WorkspaceAnalyzer};
    use crate::path_utils::rel_path_string;
    use crate::test_support::AnalyzerFixture;
    use git2::{IndexAddOption, Repository, Signature};
    use std::sync::Arc;

    fn member_fixture() -> (
        AnalyzerFixture,
        ProjectFile,
        String,
        Tree,
        ResolvedReferenceSite,
    ) {
        let source = r#"
class Service
  def run
  end
end

class Other
  def run
  end
end

def invoke
  service = Service.new
  service.run
end
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(
            Language::Ruby,
            &[("bounded_definition.rb", &source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "bounded_definition.rb");
        let tree = parse_ruby_tree(&source).expect("Ruby tree");
        let call_start = source.rfind("service.run").expect("member call");
        let start_byte = call_start + "service.".len();
        let end_byte = start_byte + "run".len();
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "run".to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line,
                end_line: start_line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        };
        (fixture, file, source, tree, site)
    }

    fn wide_deep_member_fixture() -> (
        AnalyzerFixture,
        ProjectFile,
        String,
        Tree,
        ResolvedReferenceSite,
    ) {
        let statements = (0..96)
            .map(|index| format!("  value{index} = {index}\n"))
            .collect::<String>();
        let expression = format!("{}service{}.run", "(".repeat(24), ")".repeat(24));
        let source = format!(
            "class Service\n  def run\n  end\nend\n\n\
             def invoke(service)\n{statements}  {expression}\nend\n"
        );
        let fixture =
            AnalyzerFixture::new_for_language(Language::Ruby, &[("wide_receiver.rb", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "wide_receiver.rb");
        let tree = parse_ruby_tree(&source).expect("Ruby tree");
        let expression_start = source.rfind(&expression).expect("Ruby member call");
        let start_byte = expression_start + expression.rfind("run").expect("member name");
        let end_byte = start_byte + "run".len();
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "run".to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line,
                end_line: start_line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        };
        (fixture, file, source, tree, site)
    }

    fn dispatch_mode_outcome(
        fixture: &AnalyzerFixture,
        method_fqn: &str,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> BoundedResolution<Option<RubyMethodDispatchMode>> {
        let ruby =
            resolve_analyzer::<RubyAnalyzer>(fixture.analyzer.analyzer()).expect("Ruby analyzer");
        let methods = ruby.get_definitions(method_fqn);
        let [method] = methods.as_slice() else {
            panic!("expected one Ruby method for {method_fqn}: {methods:#?}");
        };
        let session = ResolutionSession::bounded(budget, cancellation);
        let provider = RubyDefinitionProvider::new(ruby, &session);
        let mode = provider.method_dispatch_mode(method);
        session.finish(mode)
    }

    fn ruby_site(
        source: &str,
        file: &ProjectFile,
        needle: &str,
        member: &str,
    ) -> ResolvedReferenceSite {
        let expression_start = source.find(needle).expect("Ruby expression");
        let member_start =
            expression_start + needle.rfind(member).expect("Ruby member within expression");
        let line = source[..member_start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        ResolvedReferenceSite {
            path: rel_path_string(file),
            text: member.to_string(),
            range: Range {
                start_byte: member_start,
                end_byte: member_start + member.len(),
                start_line: line,
                end_line: line,
            },
            focus_start_byte: member_start,
            focus_end_byte: member_start + member.len(),
        }
    }

    #[test]
    fn bounded_definition_lookup_resolves_constructed_local_receiver() {
        let (fixture, file, source, tree, site) = member_fixture();
        let outcome = resolve_ruby_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        let BoundedResolution::Complete { value, work } = outcome else {
            panic!("Ruby member lookup should complete");
        };
        assert!(work.scope_nodes > 0);
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            matches!(
                value.definitions.as_slice(),
                [definition] if definition.fq_name() == "Service.run"
            ),
            "{value:#?}"
        );
    }

    #[test]
    fn bounded_dispatch_mode_projection_respects_budget_and_cancellation() {
        let source = r#"
class Service
  def self.build
  end
end
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("dispatch.rb", source)]);

        assert!(matches!(
            dispatch_mode_outcome(
                &fixture,
                "Service.build",
                ReceiverAnalysisBudget::default(),
                None,
            ),
            BoundedResolution::Complete {
                value: Some(RubyMethodDispatchMode::Singleton),
                ..
            }
        ));

        let budget = ReceiverAnalysisBudget::tiny();
        assert!(matches!(
            dispatch_mode_outcome(&fixture, "Service.build", budget, None),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));

        let cancellation = CancellationToken::cancel_after_checks_for_test(2);
        assert!(matches!(
            dispatch_mode_outcome(
                &fixture,
                "Service.build",
                ReceiverAnalysisBudget::default(),
                Some(&cancellation),
            ),
            BoundedResolution::Cancelled { work } if work.scope_nodes > 0
        ));
    }

    #[test]
    fn cold_cross_file_dispatch_collision_uses_limited_mode_projection() {
        let _gc_guard = crate::analyzer::store::gc::set_min_interval_secs_for_test(i64::MAX);
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let instance_source = "class Service\n  def collide\n  end\nend\n";
        let singleton_source = "class Service\n  def self.collide\n  end\nend\n";
        let other_owner_source = "class OtherService\n  def self.collide\n  end\nend\n";
        let caller_source = "class App\n  def run\n    Service.collide\n    Service.new.collide\n    OtherService.collide\n  end\nend\n";
        for (path, source) in [
            ("instance.rb", instance_source),
            ("singleton.rb", singleton_source),
            ("other_owner.rb", other_owner_source),
            ("caller.rb", caller_source),
        ] {
            ProjectFile::new(root.clone(), path)
                .write(source)
                .unwrap_or_else(|error| panic!("write {path}: {error}"));
        }
        let repository = Repository::init(&root).expect("git repository");
        let mut config = repository.config().expect("git config");
        config
            .set_str("user.name", "Bifrost Test")
            .expect("git user name");
        config
            .set_str("user.email", "bifrost@example.com")
            .expect("git user email");
        let mut index = repository.index().expect("git index");
        index
            .add_all(["*"], IndexAddOption::DEFAULT, None)
            .expect("stage Ruby fixture");
        index.write().expect("write git index");
        let tree_id = index.write_tree().expect("write git tree");
        let tree = repository.find_tree(tree_id).expect("git tree");
        let signature =
            Signature::now("Bifrost Test", "bifrost@example.com").expect("git signature");
        repository
            .commit(Some("HEAD"), &signature, &signature, "init", &tree, &[])
            .expect("commit Ruby fixture");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Ruby));
        let cold =
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .expect("cold persisted Ruby analyzer");
        drop(cold);
        let warm = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
            .expect("warm persisted Ruby analyzer");
        let analyzer = warm.analyzer();
        analyzer.reset_candidate_hydration_count_for_test();
        let ruby = resolve_analyzer::<RubyAnalyzer>(analyzer).expect("warm Ruby analyzer");
        let projection_session =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let projection_provider = RubyDefinitionProvider::new(ruby, &projection_session);
        let candidates = projection_provider.members_for_owner_name("Service", "collide");
        let projected = candidates
            .iter()
            .map(|candidate| {
                (
                    rel_path_string(candidate.source()),
                    projection_provider.method_dispatch_mode(candidate),
                )
            })
            .collect::<Vec<_>>();
        let projection_outcome = projection_session.finish(projected);
        assert!(
            matches!(
                projection_outcome,
                BoundedResolution::Complete { ref value, .. }
                    if value
                        == &vec![
                            (
                                "instance.rb".to_string(),
                                Some(RubyMethodDispatchMode::Instance),
                            ),
                            (
                                "singleton.rb".to_string(),
                                Some(RubyMethodDispatchMode::Singleton),
                            ),
                        ]
            ),
            "cold dispatch projection mismatch: {projection_outcome:#?}"
        );

        let caller = ProjectFile::new(root, "caller.rb");
        let tree = parse_ruby_tree(caller_source).expect("Ruby caller tree");
        for (needle, expected_path) in [
            ("Service.collide", "singleton.rb"),
            ("Service.new.collide", "instance.rb"),
            ("OtherService.collide", "other_owner.rb"),
        ] {
            let site = ruby_site(caller_source, &caller, needle, "collide");
            let outcome = resolve_ruby_bounded(
                analyzer,
                &caller,
                caller_source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("cold Ruby `{needle}` lookup did not complete: {outcome:#?}");
            };
            assert!(
                matches!(
                    value.definitions.as_slice(),
                    [definition]
                        if rel_path_string(definition.source()) == expected_path
                ),
                "{needle}: {value:#?}"
            );
        }
        assert_eq!(
            analyzer.full_candidate_hydration_count_for_test(),
            0,
            "bounded dispatch-mode lookup must not hydrate singleton/instance owner files"
        );
        assert_eq!(analyzer.bulk_candidate_hydration_count_for_test(), 0);
    }

    #[test]
    fn bounded_definition_lookup_does_not_fall_back_to_unrelated_same_name_methods() {
        let source = r#"
class Service
  def run
  end
end

class Other
  def run
  end
end

def invoke(unknown)
  unknown.run
end
"#
        .to_string();
        let fixture =
            AnalyzerFixture::new_for_language(Language::Ruby, &[("dynamic_receiver.rb", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "dynamic_receiver.rb");
        let tree = parse_ruby_tree(&source).expect("Ruby tree");
        let call_start = source.rfind("unknown.run").expect("member call");
        let start_byte = call_start + "unknown.".len();
        let end_byte = start_byte + "run".len();
        let line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "run".to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line: line,
                end_line: line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        };

        let outcome = resolve_ruby_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("unsupported dynamic receiver should complete explicitly");
        };
        assert!(value.definitions.is_empty(), "{value:#?}");
        assert!(
            value
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.kind == "unsupported_ruby_receiver" })
        );
    }

    #[test]
    fn bounded_type_lookup_resolves_constructed_local_receiver() {
        let (fixture, file, source, tree, method_site) = member_fixture();
        let receiver_start = source.rfind("service.run").expect("member call");
        let receiver_site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "service".to_string(),
            range: Range {
                start_byte: receiver_start,
                end_byte: receiver_start + "service".len(),
                start_line: method_site.range.start_line,
                end_line: method_site.range.end_line,
            },
            focus_start_byte: receiver_start,
            focus_end_byte: receiver_start + "service".len(),
        };
        let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let ruby =
            resolve_analyzer::<RubyAnalyzer>(fixture.analyzer.analyzer()).expect("Ruby analyzer");
        let support = RubyDefinitionProvider::new(ruby, &session);
        let resolution = ruby_type_lookup_resolution_bounded(
            &support,
            &file,
            &source,
            tree.root_node(),
            &receiver_site,
        );

        let BoundedResolution::Complete {
            value: Some(resolution),
            ..
        } = session.finish(resolution)
        else {
            panic!("Ruby receiver type lookup should complete");
        };
        assert_eq!(resolution.fqn, "Service");
        assert_eq!(
            resolution.target_kind,
            TypeLookupTargetKind::ValueExpression
        );
    }

    #[test]
    fn bounded_factory_return_resolves_exact_tail_allocation_type_and_member() {
        let source = r#"
class Service
  def run
  end
end

class Other
  def run
  end
end

class Factory
  def self.make_service
    Service.new
  end
end

def invoke
  Factory.make_service.run
end
"#
        .to_string();
        let fixture =
            AnalyzerFixture::new_for_language(Language::Ruby, &[("factory_return.rb", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "factory_return.rb");
        let tree = parse_ruby_tree(&source).expect("Ruby tree");
        let receiver_start = source
            .rfind("Factory.make_service.run")
            .expect("factory member call");
        let member_start = receiver_start + "Factory.make_service.".len();
        let line = source[..member_start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let member_site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "run".to_string(),
            range: Range {
                start_byte: member_start,
                end_byte: member_start + "run".len(),
                start_line: line,
                end_line: line,
            },
            focus_start_byte: member_start,
            focus_end_byte: member_start + "run".len(),
        };

        let member_outcome = resolve_ruby_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &member_site,
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value, .. } = member_outcome else {
            panic!("Ruby factory member lookup should complete");
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            matches!(
                value.definitions.as_slice(),
                [definition] if definition.fq_name() == "Service.run"
            ),
            "{value:#?}"
        );

        let receiver_site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "Factory.make_service".to_string(),
            range: Range {
                start_byte: receiver_start,
                end_byte: receiver_start + "Factory.make_service".len(),
                start_line: line,
                end_line: line,
            },
            focus_start_byte: receiver_start,
            focus_end_byte: receiver_start + "Factory.make_service".len(),
        };
        let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let ruby =
            resolve_analyzer::<RubyAnalyzer>(fixture.analyzer.analyzer()).expect("Ruby analyzer");
        let support = RubyDefinitionProvider::new(ruby, &session);
        let resolution = ruby_type_lookup_resolution_bounded(
            &support,
            &file,
            &source,
            tree.root_node(),
            &receiver_site,
        );
        let BoundedResolution::Complete {
            value: Some(resolution),
            ..
        } = session.finish(resolution)
        else {
            panic!("Ruby factory return type lookup should complete");
        };
        assert_eq!(resolution.fqn, "Service");
        assert_eq!(
            resolution.target_kind,
            TypeLookupTargetKind::ValueExpression
        );
    }

    #[test]
    fn bounded_factory_return_flows_through_a_plain_local_assignment() {
        let source = r#"
class Service
  def run
  end
end

class Factory
  def self.make_service
    Service.new
  end
end

def invoke
  made = Factory.make_service
  made.run
end
"#
        .to_string();
        let fixture =
            AnalyzerFixture::new_for_language(Language::Ruby, &[("factory_local.rb", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "factory_local.rb");
        let tree = parse_ruby_tree(&source).expect("Ruby tree");
        let call_start = source.rfind("made.run").expect("local member call");
        let member_start = call_start + "made.".len();
        let line = source[..member_start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "run".to_string(),
            range: Range {
                start_byte: member_start,
                end_byte: member_start + "run".len(),
                start_line: line,
                end_line: line,
            },
            focus_start_byte: member_start,
            focus_end_byte: member_start + "run".len(),
        };

        let outcome = resolve_ruby_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("Ruby factory-local member lookup should complete");
        };
        assert!(
            matches!(
                value.definitions.as_slice(),
                [definition] if definition.fq_name() == "Service.run"
            ),
            "{value:#?}"
        );
    }

    #[test]
    fn bounded_factory_return_uses_exact_limited_parent_owner() {
        let source = r#"
module Outer
  class Factory
    class Product
      def run
      end
    end

    def self.make
      Product.new
    end
  end
end

module Unrelated
  class Factory
    class Product
      def run
      end
    end
  end
end

def invoke
  Outer::Factory.make.run
end
"#
        .to_string();
        let fixture =
            AnalyzerFixture::new_for_language(Language::Ruby, &[("nested_factory.rb", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "nested_factory.rb");
        let tree = parse_ruby_tree(&source).expect("Ruby tree");
        let ruby =
            resolve_analyzer::<RubyAnalyzer>(fixture.analyzer.analyzer()).expect("Ruby analyzer");
        let methods = ruby.get_definitions("Outer$Factory.make");
        let [method] = methods.as_slice() else {
            panic!("expected nested factory method: {methods:#?}");
        };
        assert_eq!(method.fq_name(), "Outer$Factory.make");
        assert_eq!(method.identifier(), "make");
        let owners = ruby.get_definitions("Outer$Factory");
        assert!(
            owners
                .iter()
                .any(|owner| owner.fq_name() == "Outer$Factory"),
            "expected nested factory owner: {owners:#?}"
        );
        let parent_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let parent_provider = RubyDefinitionProvider::new(ruby, &parent_session);
        let parent = parent_provider.parent(method);
        let parent_outcome = parent_session.finish(parent);
        let BoundedResolution::Complete {
            value: Some(parent),
            ..
        } = parent_outcome
        else {
            panic!("bounded nested factory parent was not proven: {parent_outcome:#?}");
        };
        assert_eq!(parent.fq_name(), "Outer$Factory");
        let call_start = source
            .rfind("Outer::Factory.make.run")
            .expect("nested factory call");
        let member_start = call_start + "Outer::Factory.make.".len();
        let line = source[..member_start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "run".to_string(),
            range: Range {
                start_byte: member_start,
                end_byte: member_start + "run".len(),
                start_line: line,
                end_line: line,
            },
            focus_start_byte: member_start,
            focus_end_byte: member_start + "run".len(),
        };

        let outcome = resolve_ruby_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("nested Ruby factory lookup should complete: {outcome:#?}");
        };
        assert!(
            matches!(
                value.definitions.as_slice(),
                [definition] if definition.fq_name() == "Outer$Factory$Product.run"
            ),
            "{value:#?}"
        );
    }

    #[test]
    fn bounded_constant_path_walk_is_iterative_and_budgeted() {
        let expected = (0..128)
            .map(|index| format!("Namespace{index}"))
            .collect::<Vec<_>>();
        let source = format!("{}\n", expected.join("::"));
        let fixture =
            AnalyzerFixture::new_for_language(Language::Ruby, &[("deep_constant.rb", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "deep_constant.rb");
        let tree = parse_ruby_tree(&source).expect("Ruby tree");
        let path_node = tree
            .root_node()
            .named_child(0)
            .expect("qualified constant expression");
        assert_eq!(path_node.kind(), "scope_resolution");
        let ruby =
            resolve_analyzer::<RubyAnalyzer>(fixture.analyzer.analyzer()).expect("Ruby analyzer");

        let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let support = RubyDefinitionProvider::new(ruby, &session);
        let context =
            BoundedRubyLookupContext::build(&support, &file, &source, tree.root_node(), 0);
        let path = context
            .constant_name_path(path_node)
            .expect("deep path should fit the ordinary receiver budget");
        assert_eq!(path.segments, expected);
        assert!(!path.absolute);
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Complete { .. }
        ));

        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 32,
            ..ReceiverAnalysisBudget::default()
        };
        let session = ResolutionSession::bounded(budget, None);
        let support = RubyDefinitionProvider::new(ruby, &session);
        let context =
            BoundedRubyLookupContext::build(&support, &file, &source, tree.root_node(), 0);
        assert!(context.constant_name_path(path_node).is_none());
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));
    }

    #[test]
    fn bounded_definition_lookup_stops_at_scope_budget() {
        let (fixture, file, source, tree, site) = wide_deep_member_fixture();
        let budget = ReceiverAnalysisBudget::tiny();
        let outcome = resolve_ruby_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            budget,
            None,
        );

        assert!(matches!(
            outcome,
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));
    }

    #[test]
    fn bounded_definition_lookup_stops_on_cancellation() {
        let (fixture, file, source, tree, site) = wide_deep_member_fixture();
        let cancellation = CancellationToken::cancel_after_checks_for_test(12);
        let outcome = resolve_ruby_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            Some(&cancellation),
        );

        assert!(matches!(outcome, BoundedResolution::Cancelled { .. }));
    }

    fn parenthesized_receiver_outcome(
        depth: usize,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> BoundedResolution<bool> {
        let expression = format!("{}Service{}", "(".repeat(depth), ")".repeat(depth));
        let source = format!("class Service\nend\n{expression}\n");
        let fixture = AnalyzerFixture::new_for_language(
            Language::Ruby,
            &[("parenthesized_receiver.rb", &source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "parenthesized_receiver.rb");
        let tree = parse_ruby_tree(&source).expect("Ruby tree");
        let expression_node = tree
            .root_node()
            .named_child(tree.root_node().named_child_count().saturating_sub(1))
            .expect("parenthesized receiver expression");
        let session = ResolutionSession::bounded(budget, cancellation);
        let ruby =
            resolve_analyzer::<RubyAnalyzer>(fixture.analyzer.analyzer()).expect("Ruby analyzer");
        let support = RubyDefinitionProvider::new(ruby, &session);
        let context = BoundedRubyLookupContext::build(
            &support,
            &file,
            &source,
            tree.root_node(),
            expression_node.start_byte(),
        );
        let resolved = context.expression_receiver_type(expression_node).is_some();
        session.finish(resolved)
    }

    #[test]
    fn parenthesized_receiver_unwrap_is_fully_budgeted_and_cancellable() {
        let BoundedResolution::Complete {
            value: true,
            work: shallow_work,
        } = parenthesized_receiver_outcome(1, ReceiverAnalysisBudget::default(), None)
        else {
            panic!("shallow parenthesized Ruby receiver should resolve");
        };
        let BoundedResolution::Complete {
            value: true,
            work: deep_work,
        } = parenthesized_receiver_outcome(256, ReceiverAnalysisBudget::default(), None)
        else {
            panic!("deep parenthesized Ruby receiver should resolve iteratively");
        };
        assert!(
            deep_work.scope_nodes >= shallow_work.scope_nodes + 255,
            "each parenthesis transition must be charged: shallow={shallow_work:?}, deep={deep_work:?}"
        );

        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: deep_work.scope_nodes.saturating_sub(1),
            ..ReceiverAnalysisBudget::default()
        };
        assert!(matches!(
            parenthesized_receiver_outcome(256, budget, None),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));

        let cancellation =
            CancellationToken::cancel_after_checks_for_test(shallow_work.scope_nodes + 16);
        assert!(matches!(
            parenthesized_receiver_outcome(
                256,
                ReceiverAnalysisBudget::default(),
                Some(&cancellation),
            ),
            BoundedResolution::Cancelled { .. }
        ));
    }
}
