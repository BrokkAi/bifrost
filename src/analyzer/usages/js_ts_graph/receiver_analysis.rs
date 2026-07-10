//! JavaScript / TypeScript receiver facts for bounded object-sensitive usage analysis.
//!
//! This provider intentionally starts with the small, structurally proven forms that
//! issue #394 needs first: local receivers assigned from `new Class()`, top-level
//! factory calls that return constructed values, and class factory methods whose body
//! returns a constructed value.

use crate::analyzer::js_ts::syntax::slice;
use crate::analyzer::usages::get_definition::js_ts::{
    parse_js_ts_tree, resolve_js_ts_module_binding_candidates,
    ts_resolve_type_text_to_property_owners, ts_type_annotation_text,
};
use crate::analyzer::usages::js_ts_graph::compute_jsts_import_binder;
use crate::analyzer::usages::model::{ImportBinder, ImportKind};
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisBudgetTracker, ReceiverAnalysisCacheKey,
    ReceiverAnalysisOutcome, ReceiverAnalysisQuery, ReceiverContext, ReceiverFactProvider,
    ReceiverSummaryQuery, ReceiverValue,
};
use crate::analyzer::{
    AliasResolver, CodeUnit, DefinitionLookupIndex, IAnalyzer, Language, ProjectFile, Range,
};
use crate::hash::{HashMap, HashSet};
use crate::profiling;
use std::cell::RefCell;
use tree_sitter::Node;

const MAX_JSTS_RECEIVER_RECURSION: usize = 8;

pub(crate) struct JsTsReceiverFactProvider<'tree, 'a> {
    analyzer: &'a dyn IAnalyzer,
    support: &'a DefinitionLookupIndex,
    language: Language,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'tree>,
    imports: ImportBinder,
    aliases: AliasResolver,
    function_declarations_by_name: HashMap<String, Vec<Node<'tree>>>,
    class_declarations_by_name: HashMap<String, Vec<Node<'tree>>>,
    member_target_cache:
        RefCell<HashMap<ReceiverAnalysisCacheKey, ReceiverAnalysisOutcome<CodeUnit>>>,
}

impl<'tree, 'a> JsTsReceiverFactProvider<'tree, 'a> {
    pub(crate) fn new(
        analyzer: &'a dyn IAnalyzer,
        support: &'a DefinitionLookupIndex,
        language: Language,
        file: &'a ProjectFile,
        source: &'a str,
        root: Node<'tree>,
        imports: ImportBinder,
    ) -> Self {
        let (function_declarations_by_name, class_declarations_by_name) =
            index_js_ts_declarations(root, source);
        let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());
        Self {
            analyzer,
            support,
            language,
            file,
            source,
            root,
            imports,
            aliases,
            function_declarations_by_name,
            class_declarations_by_name,
            member_target_cache: RefCell::new(HashMap::default()),
        }
    }

    pub(crate) fn resolve_member_targets(
        &self,
        receiver: Node<'tree>,
        member: &str,
        _before_byte: usize,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<CodeUnit> {
        let _scope = profiling::scope("jsts.receiver_analysis.resolve_member_targets");
        let query = ReceiverAnalysisQuery {
            language: self.language,
            file: self.file,
            receiver_text: slice(receiver, self.source),
            receiver_range: Some(node_range(receiver)),
            member_name: Some(member),
            context: ReceiverContext::new(None, receiver.start_byte()),
            budget,
        };
        let cache_key = ReceiverAnalysisCacheKey::for_receiver(&query);
        if let Some(cached) = self.member_target_cache.borrow().get(&cache_key).cloned() {
            return cached;
        }
        let mut tracker = ReceiverAnalysisBudgetTracker::new(budget);
        let outcome = match self.resolve_expression(receiver, 0, budget, &mut tracker) {
            ReceiverAnalysisOutcome::Precise(values) => {
                let targets = values
                    .iter()
                    .flat_map(|value| self.member_targets(value.owner(), member))
                    .collect::<Vec<_>>();
                ReceiverAnalysisOutcome::single_precise_or_ambiguous(targets, budget)
            }
            ReceiverAnalysisOutcome::Ambiguous(values) => {
                let targets = values
                    .iter()
                    .flat_map(|value| self.member_targets(value.owner(), member))
                    .collect::<Vec<_>>();
                if targets.is_empty() {
                    ReceiverAnalysisOutcome::Ambiguous(Vec::new())
                } else {
                    ReceiverAnalysisOutcome::Ambiguous(dedup_units(targets, budget.max_targets))
                }
            }
            ReceiverAnalysisOutcome::Unknown => ReceiverAnalysisOutcome::Unknown,
            ReceiverAnalysisOutcome::Unsupported { reason } => {
                ReceiverAnalysisOutcome::Unsupported { reason }
            }
            ReceiverAnalysisOutcome::ExceededBudget { limit } => {
                ReceiverAnalysisOutcome::ExceededBudget { limit }
            }
        };
        self.member_target_cache
            .borrow_mut()
            .insert(cache_key, outcome.clone());
        outcome
    }

    pub(crate) fn resolve_contextual_object_literal_key_targets(
        &self,
        key: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> Vec<CodeUnit> {
        if self.language != Language::TypeScript {
            return Vec::new();
        }
        let Some((property, object, member)) = object_literal_property_at_key(key, self.source)
        else {
            return Vec::new();
        };
        if !(property.start_byte() <= key.start_byte() && key.end_byte() <= property.end_byte()) {
            return Vec::new();
        }
        let owners = self.contextual_object_literal_receiver_values(object, budget);
        let mut targets = owners
            .iter()
            .flat_map(|value| self.member_targets(value.owner(), &member))
            .collect::<Vec<_>>();
        sort_units(&mut targets);
        targets.dedup();
        targets.truncate(budget.max_targets.saturating_add(1));
        targets
    }

    fn resolve_expression(
        &self,
        expression: Node<'tree>,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        if depth > MAX_JSTS_RECEIVER_RECURSION {
            return ReceiverAnalysisOutcome::ExceededBudget {
                limit: "receiver_recursion",
            };
        }
        match expression.kind() {
            "new_expression" => self.resolve_new_expression(expression, budget),
            "object" if self.language == Language::JavaScript => {
                self.resolve_object_expression(expression, budget)
            }
            "this" => self.resolve_this_expression(expression, budget),
            "call_expression" => self.summarize_call_node(
                expression,
                expression.start_byte(),
                depth + 1,
                budget,
                tracker,
            ),
            "identifier" | "type_identifier" => {
                let name = slice(expression, self.source);
                if name.is_empty() {
                    ReceiverAnalysisOutcome::Unknown
                } else {
                    self.resolve_identifier_binding(expression, name, depth + 1, budget, tracker)
                }
            }
            "conditional_expression" | "ternary_expression" => {
                let mut outcomes = Vec::new();
                for field in ["consequence", "alternative"] {
                    if let Some(branch) = expression.child_by_field_name(field) {
                        outcomes.push(self.resolve_expression(branch, depth + 1, budget, tracker));
                    }
                }
                ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget)
            }
            "parenthesized_expression" | "await_expression" => expression
                .named_child(0)
                .map(|child| self.resolve_expression(child, depth + 1, budget, tracker))
                .unwrap_or(ReceiverAnalysisOutcome::Unknown),
            _ => ReceiverAnalysisOutcome::Unknown,
        }
    }

    fn resolve_new_expression(
        &self,
        expression: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let Some(constructor) = expression.child_by_field_name("constructor") else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let Some(name) = simple_identifier_text(constructor, self.source) else {
            return ReceiverAnalysisOutcome::Unsupported {
                reason: "unsupported_constructor_receiver",
            };
        };
        let values = self
            .class_units_named(name, expression)
            .into_iter()
            .map(|ty| ReceiverValue::AllocationSite {
                ty,
                file: self.file.clone(),
                range: node_range(expression),
            })
            .collect::<Vec<_>>();
        ReceiverAnalysisOutcome::single_precise_or_ambiguous(values, budget)
    }

    fn resolve_this_expression(
        &self,
        expression: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let Some(class_node) = enclosing_class_scope(expression) else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let Some(name_node) = class_node.child_by_field_name("name") else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let Some(name) = simple_identifier_text(name_node, self.source) else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let values = self
            .class_units_named(name, expression)
            .into_iter()
            .map(ReceiverValue::CurrentReceiver)
            .collect::<Vec<_>>();
        ReceiverAnalysisOutcome::single_precise_or_ambiguous(values, budget)
    }

    fn resolve_object_expression(
        &self,
        expression: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let Some(declarator) = expression
            .parent()
            .filter(|parent| parent.kind() == "variable_declarator")
        else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        if declarator
            .child_by_field_name("value")
            .is_none_or(|value| value.id() != expression.id())
        {
            return ReceiverAnalysisOutcome::Unknown;
        }
        let Some(name) = declarator
            .child_by_field_name("name")
            .and_then(|name| simple_identifier_text(name, self.source))
        else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let values = self
            .support
            .file_identifier(self.file, name)
            .into_iter()
            .filter(|unit| unit.source() == self.file && unit.is_field())
            .map(ReceiverValue::ModuleOrExportObject)
            .collect::<Vec<_>>();
        ReceiverAnalysisOutcome::single_precise_or_ambiguous(values, budget)
    }

    fn resolve_identifier_binding(
        &self,
        receiver_node: Node<'tree>,
        receiver: &str,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let before_byte = receiver_node.start_byte();
        let scopes = lexical_scopes_for_node(receiver_node);
        if scopes.is_empty() {
            return ReceiverAnalysisOutcome::Unknown;
        };
        for scope in scopes {
            if let Some(outcome) = self.latest_identifier_binding_in_scope(
                scope,
                receiver,
                before_byte,
                depth,
                budget,
                tracker,
            ) {
                return outcome;
            }
        }
        ReceiverAnalysisOutcome::Unknown
    }

    fn latest_identifier_binding_in_scope(
        &self,
        scope: Node<'tree>,
        receiver: &str,
        before_byte: usize,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> Option<ReceiverAnalysisOutcome<ReceiverValue>> {
        let mut latest = None;
        let mut stack = vec![scope];
        while let Some(node) = stack.pop() {
            if let Err(limit) = tracker.record_scope_node() {
                return Some(limit.exceeded());
            }
            if node.start_byte() >= before_byte {
                continue;
            }
            if node.id() != scope.id() && is_scope_boundary(node.kind()) {
                continue;
            }
            if self.language == Language::TypeScript
                && matches!(node.kind(), "required_parameter" | "optional_parameter")
                && node
                    .child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("pattern"))
                    .is_some_and(|name| node_text_matches(name, self.source, receiver))
                && let Some(type_node) = node.child_by_field_name("type")
            {
                let values = self.type_annotation_receiver_values(type_node, budget);
                latest = Some(if values.is_empty() {
                    ReceiverAnalysisOutcome::Unknown
                } else {
                    ReceiverAnalysisOutcome::single_precise_or_ambiguous(values, budget)
                });
            } else if binding_node_shadows_receiver(node, self.source, receiver) {
                latest = Some(ReceiverAnalysisOutcome::Unknown);
            } else if node.kind() == "variable_declarator"
                && let Some(name) = node.child_by_field_name("name")
                && node_text_matches(name, self.source, receiver)
            {
                latest = Some(self.resolve_variable_declarator_binding(
                    node,
                    depth + 1,
                    budget,
                    tracker,
                ));
            } else if node.kind() == "assignment_expression"
                && let Some(left) = node.child_by_field_name("left")
                && matches!(left.kind(), "identifier" | "type_identifier")
                && node_text_matches(left, self.source, receiver)
            {
                if assignment_has_nonlinear_control_ancestor(node, scope) {
                    latest = Some(ReceiverAnalysisOutcome::Ambiguous(Vec::new()));
                } else {
                    latest = Some(
                        node.child_by_field_name("right")
                            .map(|right| self.resolve_expression(right, depth + 1, budget, tracker))
                            .unwrap_or(ReceiverAnalysisOutcome::Unknown),
                    );
                }
            }

            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
        latest
    }

    fn resolve_variable_declarator_binding(
        &self,
        declarator: Node<'tree>,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        if self.language == Language::TypeScript
            && let Some(type_node) = declarator.child_by_field_name("type")
        {
            let owners = self.type_annotation_receiver_values(type_node, budget);
            if !owners.is_empty() {
                return ReceiverAnalysisOutcome::single_precise_or_ambiguous(owners, budget);
            }
        }
        declarator
            .child_by_field_name("value")
            .map(|value| self.resolve_expression(value, depth + 1, budget, tracker))
            .unwrap_or(ReceiverAnalysisOutcome::Unknown)
    }

    fn type_annotation_receiver_values(
        &self,
        type_node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> Vec<ReceiverValue> {
        ts_resolve_type_text_to_property_owners(
            self.analyzer,
            self.support,
            self.file,
            self.source,
            &self.imports,
            &self.aliases,
            ts_type_annotation_text(type_node, self.source).as_str(),
            0,
        )
        .into_iter()
        .take(budget.max_targets)
        .map(ReceiverValue::InstanceType)
        .collect()
    }

    fn contextual_object_literal_receiver_values(
        &self,
        object: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> Vec<ReceiverValue> {
        if let Some(variable) = object
            .parent()
            .filter(|parent| parent.kind() == "variable_declarator")
            && variable
                .child_by_field_name("value")
                .is_some_and(|value| value.id() == object.id())
            && let Some(type_node) = variable.child_by_field_name("type")
        {
            return self.type_annotation_receiver_values(type_node, budget);
        }

        let Some(return_statement) = object
            .parent()
            .filter(|parent| parent.kind() == "return_statement")
        else {
            return Vec::new();
        };
        let mut cursor = return_statement.walk();
        if return_statement
            .named_children(&mut cursor)
            .next()
            .is_none_or(|value| value.id() != object.id())
        {
            return Vec::new();
        }
        let Some(function) = enclosing_function_scope(object) else {
            return Vec::new();
        };
        let Some(type_node) = function.child_by_field_name("return_type") else {
            return Vec::new();
        };
        self.type_annotation_receiver_values(type_node, budget)
    }

    fn resolve_static_object_expression(
        &self,
        expression: Node<'tree>,
        _call_byte: usize,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let Some(name) = simple_identifier_text(expression, self.source) else {
            return ReceiverAnalysisOutcome::Unsupported {
                reason: "unsupported_static_factory_receiver",
            };
        };
        ReceiverAnalysisOutcome::single_precise_or_ambiguous(
            self.class_units_named(name, expression)
                .into_iter()
                .map(ReceiverValue::ClassOrStaticObject),
            budget,
        )
    }

    fn summarize_call_node(
        &self,
        call: Node<'tree>,
        call_byte: usize,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        if let Err(limit) = tracker.record_summary_expansion() {
            return limit.exceeded();
        }
        let Some(function) = call.child_by_field_name("function") else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        match function.kind() {
            "identifier" | "type_identifier" => {
                let name = slice(function, self.source);
                self.summarize_named_function(name, call, depth + 1, budget, tracker)
            }
            "member_expression" => {
                self.summarize_member_call(function, call_byte, depth + 1, budget, tracker)
            }
            _ => ReceiverAnalysisOutcome::Unsupported {
                reason: "unsupported_call_callee",
            },
        }
    }

    fn summarize_named_function(
        &self,
        name: &str,
        site: Node<'tree>,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        if name.is_empty() {
            return ReceiverAnalysisOutcome::Unknown;
        }
        let functions = self.visible_function_declarations_named(name, site);
        let mut outcomes: Vec<_> = functions
            .into_iter()
            .map(|function| self.summarize_function_body(function, depth + 1, budget, tracker))
            .collect();
        if let Some(imported) = self.summarize_imported_function(name, depth + 1, budget, tracker) {
            outcomes.push(imported);
        }
        if outcomes.is_empty() {
            return ReceiverAnalysisOutcome::Unknown;
        }
        ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget)
    }

    fn summarize_imported_function(
        &self,
        name: &str,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> Option<ReceiverAnalysisOutcome<ReceiverValue>> {
        if self.language != Language::JavaScript {
            return None;
        }
        let binding = self.imports.bindings.get(name)?;
        if !matches!(binding.kind, ImportKind::Named | ImportKind::Default) {
            return None;
        }
        let exported_name = match binding.kind {
            ImportKind::Named => binding.imported_name.as_deref().unwrap_or(name),
            ImportKind::Default => "default",
            ImportKind::Namespace | ImportKind::CommonJsRequire | ImportKind::Glob => return None,
        };
        let functions = resolve_js_ts_module_binding_candidates(
            self.analyzer,
            self.support,
            self.language,
            self.file,
            &binding.module_specifier,
            exported_name,
            Some(&self.aliases),
            true,
        )
        .into_iter()
        .filter(|unit| unit.is_function())
        .collect::<Vec<_>>();
        if functions.is_empty() {
            return None;
        }

        let mut outcomes = Vec::new();
        for function in functions {
            let Ok(source) = function.source().read_to_string() else {
                continue;
            };
            let Some(tree) = parse_js_ts_tree(function.source(), &source, self.language) else {
                continue;
            };
            let imports = compute_jsts_import_binder(&source, &tree);
            let provider = JsTsReceiverFactProvider::new(
                self.analyzer,
                self.support,
                self.language,
                function.source(),
                &source,
                tree.root_node(),
                imports,
            );
            for node in nodes_for_code_unit(self.analyzer, &function, tree.root_node()) {
                outcomes.push(provider.summarize_function_body(node, depth + 1, budget, tracker));
            }
        }
        (!outcomes.is_empty())
            .then(|| ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget))
    }

    fn summarize_member_call(
        &self,
        member_expression: Node<'tree>,
        call_byte: usize,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let Some(object) = member_expression.child_by_field_name("object") else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let Some(property) = member_expression.child_by_field_name("property") else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let member = slice(property, self.source);
        if member.is_empty() {
            return ReceiverAnalysisOutcome::Unknown;
        }
        let class_values = self.resolve_static_object_expression(object, call_byte, budget);
        let ReceiverAnalysisOutcome::Precise(values) = class_values else {
            return class_values;
        };
        let mut methods = Vec::new();
        for value in values {
            methods.extend(self.class_method_nodes(value.owner(), member));
        }
        if methods.is_empty() {
            return ReceiverAnalysisOutcome::Unknown;
        }
        let outcomes: Vec<_> = methods
            .into_iter()
            .map(|method| self.summarize_function_body(method, depth + 1, budget, tracker))
            .collect();
        ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget)
    }

    fn summarize_function_body(
        &self,
        function: Node<'tree>,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        if depth > MAX_JSTS_RECEIVER_RECURSION {
            return ReceiverAnalysisOutcome::ExceededBudget {
                limit: "receiver_recursion",
            };
        }
        let mut outcomes = Vec::new();
        let mut stack = vec![function];
        while let Some(node) = stack.pop() {
            if let Err(limit) = tracker.record_scope_node() {
                return limit.exceeded();
            }
            if node.id() != function.id() && is_summary_boundary(node.kind()) {
                continue;
            }
            if node.kind() == "return_statement" {
                let mut cursor = node.walk();
                if let Some(value) = node.named_children(&mut cursor).next() {
                    outcomes.push(self.resolve_expression(value, depth + 1, budget, tracker));
                }
                continue;
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
        ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget)
    }

    fn class_units_named(&self, name: &str, site: Node<'tree>) -> Vec<CodeUnit> {
        if self.visible_class_declaration_nodes(name, site).is_empty() {
            return Vec::new();
        }
        let mut units = self
            .analyzer
            .declarations(self.file)
            .into_iter()
            .filter(|unit| {
                unit.is_class()
                    && unit.identifier() == name
                    && crate::analyzer::common::language_for_file(unit.source()) == self.language
            })
            .collect::<Vec<_>>();
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn member_targets(&self, owner: &CodeUnit, member: &str) -> Vec<CodeUnit> {
        let fqn = format!("{}.{}", owner.fq_name(), member);
        let mut units = self
            .analyzer
            .definitions(&fqn)
            .filter(|unit| unit.source() == owner.source())
            .filter(|unit| unit.is_function() || unit.is_field())
            .collect::<Vec<_>>();
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn visible_function_declarations_named(
        &self,
        name: &str,
        site: Node<'tree>,
    ) -> Vec<Node<'tree>> {
        let visible_scopes = lexical_scope_ids_for_node(site);
        self.function_declarations_by_name
            .get(name)
            .map(|functions| {
                functions
                    .iter()
                    .copied()
                    .filter(|function| {
                        declaration_scope_id(*function)
                            .is_some_and(|id| visible_scopes.contains(&id))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn class_method_nodes(&self, owner: &CodeUnit, member: &str) -> Vec<Node<'tree>> {
        let mut methods = Vec::new();
        for class_node in self.class_declaration_nodes(owner.identifier()) {
            let Some(body) = class_node.child_by_field_name("body") else {
                continue;
            };
            let mut cursor = body.walk();
            for child in body.named_children(&mut cursor) {
                if child.kind() == "method_definition"
                    && child
                        .child_by_field_name("name")
                        .is_some_and(|name| node_text_matches(name, self.source, member))
                {
                    methods.push(child);
                }
            }
        }
        methods
    }

    fn class_declaration_nodes(&self, name: &str) -> Vec<Node<'tree>> {
        self.class_declarations_by_name
            .get(name)
            .cloned()
            .unwrap_or_default()
    }

    fn visible_class_declaration_nodes(&self, name: &str, site: Node<'tree>) -> Vec<Node<'tree>> {
        let visible_scopes = lexical_scope_ids_for_node(site);
        self.class_declarations_by_name
            .get(name)
            .map(|classes| {
                classes
                    .iter()
                    .copied()
                    .filter(|class| {
                        declaration_scope_id(*class).is_some_and(|id| visible_scopes.contains(&id))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl ReceiverFactProvider for JsTsReceiverFactProvider<'_, '_> {
    fn resolve_receiver(
        &self,
        query: ReceiverAnalysisQuery<'_>,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let _scope = profiling::scope("jsts.receiver_analysis.resolve_receiver");
        let mut tracker = ReceiverAnalysisBudgetTracker::new(query.budget);
        let Some(range) = query.receiver_range else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let Some(node) = smallest_named_node_covering(self.root, range.start_byte, range.end_byte)
        else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        self.resolve_expression(node, 0, query.budget, &mut tracker)
    }

    fn summarize_call_result(
        &self,
        query: ReceiverSummaryQuery<'_>,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let _scope = profiling::scope("jsts.receiver_analysis.summarize_call_result");
        let mut tracker = ReceiverAnalysisBudgetTracker::new(query.budget);
        let Some(range) = query.call_range else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let Some(node) = smallest_named_node_covering(self.root, range.start_byte, range.end_byte)
        else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        if node.kind() != "call_expression" {
            return ReceiverAnalysisOutcome::Unsupported {
                reason: "summary_query_not_call_expression",
            };
        }
        self.summarize_call_node(node, query.context.byte, 0, query.budget, &mut tracker)
    }
}

fn lexical_scopes_for_node<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    let mut scopes = Vec::new();
    let mut current = node;
    loop {
        if is_scope_boundary(current.kind()) {
            scopes.push(current);
        }
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent;
    }
    scopes
}

fn enclosing_function_scope<'tree>(mut node: Node<'tree>) -> Option<Node<'tree>> {
    loop {
        if matches!(
            node.kind(),
            "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
        ) {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn enclosing_class_scope<'tree>(mut node: Node<'tree>) -> Option<Node<'tree>> {
    loop {
        if matches!(
            node.kind(),
            "class_declaration" | "abstract_class_declaration" | "class"
        ) {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn object_literal_property_at_key<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, Node<'tree>, String)> {
    let property = match node.kind() {
        "pair" | "shorthand_property_identifier" | "method_definition" => node,
        _ => node.parent().filter(|parent| {
            matches!(
                parent.kind(),
                "pair" | "shorthand_property_identifier" | "method_definition"
            ) && parent
                .child_by_field_name("key")
                .or_else(|| parent.child_by_field_name("name"))
                .or_else(|| parent.named_child(0))
                .is_some_and(|key| key.id() == node.id())
        })?,
    };
    let object = property
        .parent()
        .filter(|parent| parent.kind() == "object")?;
    let member = crate::analyzer::typescript::ts_object_literal_property_name(property, source)?;
    Some((property, object, member))
}

fn lexical_scope_ids_for_node(node: Node<'_>) -> HashSet<usize> {
    lexical_scopes_for_node(node)
        .into_iter()
        .map(|scope| scope.id())
        .collect()
}

fn binding_node_shadows_receiver(node: Node<'_>, source: &str, receiver: &str) -> bool {
    match node.kind() {
        "formal_parameter" | "required_parameter" | "optional_parameter" | "rest_pattern"
        | "catch_clause" => node
            .child_by_field_name("pattern")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.child_by_field_name("parameter"))
            .is_some_and(|pattern| binding_pattern_contains_name(pattern, source, receiver)),
        "variable_declarator" => node.child_by_field_name("name").is_some_and(|pattern| {
            !matches!(pattern.kind(), "identifier" | "type_identifier")
                && binding_pattern_contains_name(pattern, source, receiver)
        }),
        "identifier" | "type_identifier" => {
            node.parent()
                .is_some_and(|parent| matches!(parent.kind(), "formal_parameters" | "parameters"))
                && node_text_matches(node, source, receiver)
        }
        _ => false,
    }
}

fn binding_pattern_contains_name(node: Node<'_>, source: &str, receiver: &str) -> bool {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "identifier" | "type_identifier" | "shorthand_property_identifier_pattern"
        ) && node_text_matches(node, source, receiver)
        {
            return true;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    false
}

fn declaration_scope_id(node: Node<'_>) -> Option<usize> {
    let mut current = node.parent()?;
    loop {
        if is_scope_boundary(current.kind()) {
            return Some(current.id());
        }
        current = current.parent()?;
    }
}

fn assignment_has_nonlinear_control_ancestor(assignment: Node<'_>, scope: Node<'_>) -> bool {
    let mut current = assignment.parent();
    while let Some(node) = current {
        if node.id() == scope.id() || is_scope_boundary(node.kind()) {
            return false;
        }
        if is_nonlinear_control_boundary(node.kind()) {
            return true;
        }
        current = node.parent();
    }
    false
}

fn is_nonlinear_control_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "if_statement"
            | "else_clause"
            | "switch_statement"
            | "switch_case"
            | "for_statement"
            | "for_in_statement"
            | "while_statement"
            | "do_statement"
            | "try_statement"
            | "catch_clause"
    )
}

fn smallest_named_node_covering<'tree>(
    root: Node<'tree>,
    start_byte: usize,
    end_byte: usize,
) -> Option<Node<'tree>> {
    if start_byte < root.start_byte() || root.end_byte() < end_byte {
        return None;
    }
    let mut best = root;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if start_byte < node.start_byte() || node.end_byte() < end_byte {
            continue;
        }
        if node.end_byte() - node.start_byte() <= best.end_byte() - best.start_byte() {
            best = node;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    Some(best)
}

fn nodes_for_code_unit<'tree>(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    root: Node<'tree>,
) -> Vec<Node<'tree>> {
    analyzer
        .ranges(unit)
        .iter()
        .filter_map(|range| smallest_named_node_covering(root, range.start_byte, range.end_byte))
        .map(|node| {
            node.child_by_field_name("declaration")
                .filter(|_| node.kind() == "export_statement")
                .unwrap_or(node)
        })
        .collect()
}

fn is_scope_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "program"
            | "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
            | "statement_block"
            | "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
    )
}

fn is_summary_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
            | "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
    )
}

fn index_js_ts_declarations<'tree>(
    root: Node<'tree>,
    source: &str,
) -> (
    HashMap<String, Vec<Node<'tree>>>,
    HashMap<String, Vec<Node<'tree>>>,
) {
    let mut functions: HashMap<String, Vec<Node<'tree>>> = HashMap::default();
    let mut classes: HashMap<String, Vec<Node<'tree>>> = HashMap::default();
    let mut seen = HashSet::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !seen.insert(node.id()) {
            continue;
        }
        if node.kind() == "function_declaration"
            && let Some(name_node) = node.child_by_field_name("name")
            && let Some(name) = simple_identifier_text(name_node, source)
        {
            functions.entry(name.to_string()).or_default().push(node);
        } else if matches!(
            node.kind(),
            "class_declaration" | "abstract_class_declaration"
        ) && let Some(name_node) = node.child_by_field_name("name")
            && let Some(name) = simple_identifier_text(name_node, source)
        {
            classes.entry(name.to_string()).or_default().push(node);
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    (functions, classes)
}

fn simple_identifier_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "identifier" | "type_identifier" => {
            let text = slice(node, source);
            (!text.is_empty()).then_some(text)
        }
        _ => None,
    }
}

fn node_text_matches(node: Node<'_>, source: &str, expected: &str) -> bool {
    slice(node, source) == expected
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    }
}

fn sort_units(units: &mut [CodeUnit]) {
    units.sort_by(|left, right| {
        left.source()
            .cmp(right.source())
            .then_with(|| left.fq_name().cmp(&right.fq_name()))
    });
}

fn dedup_units(mut units: Vec<CodeUnit>, limit: usize) -> Vec<CodeUnit> {
    sort_units(&mut units);
    units.dedup();
    units.truncate(limit.saturating_add(1));
    units
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::receiver_analysis::DEFAULT_RECEIVER_MAX_TARGETS;
    use crate::analyzer::{ProjectFile, TestProject, TypescriptAnalyzer};
    use std::path::PathBuf;
    use tree_sitter::Parser;

    fn test_project(source: &str) -> (tempfile::TempDir, ProjectFile, TypescriptAnalyzer) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("src/app.ts"));
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        (temp, file, analyzer)
    }

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("typescript parser");
        parser.parse(source, None).expect("parse source")
    }

    fn receiver_node<'tree>(
        root: Node<'tree>,
        source: &str,
        marker: &str,
        receiver: &str,
    ) -> Node<'tree> {
        let marker_start = source.find(marker).expect("marker");
        let receiver_start = source[marker_start..]
            .find(receiver)
            .map(|offset| marker_start + offset)
            .expect("receiver");
        smallest_named_node_covering(root, receiver_start, receiver_start + receiver.len())
            .expect("receiver node")
    }

    #[test]
    fn tiny_scope_budget_exits_without_precise_targets() {
        let source = r#"
class Service { run() {} }
function makeService() { return new Service(); }
export function caller() {
  const service = makeService();
  service.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);
        let tree = parse(source);
        let provider = JsTsReceiverFactProvider::new(
            &analyzer,
            analyzer.definition_lookup_index(),
            Language::TypeScript,
            &file,
            source,
            tree.root_node(),
            ImportBinder::empty(),
        );
        let receiver = receiver_node(tree.root_node(), source, "service.run", "service");

        let outcome = provider.resolve_member_targets(
            receiver,
            "run",
            receiver.start_byte(),
            ReceiverAnalysisBudget::tiny(),
        );

        assert_eq!(
            outcome,
            ReceiverAnalysisOutcome::ExceededBudget {
                limit: "scope_nodes"
            }
        );
        assert!(outcome.is_terminal_for_graph());
    }

    #[test]
    fn scope_node_budget_is_per_receiver_query() {
        let source = r#"
class Service { run() {} }
function makeService() { return new Service(); }
export function first() {
  const a0 = 0; const a1 = 1; const a2 = 2; const a3 = 3; const a4 = 4;
  const a5 = 5; const a6 = 6; const a7 = 7; const a8 = 8; const a9 = 9;
  const service = makeService();
  // first call
  service.run();
}
export function second() {
  const b0 = 0; const b1 = 1; const b2 = 2; const b3 = 3; const b4 = 4;
  const b5 = 5; const b6 = 6; const b7 = 7; const b8 = 8; const b9 = 9;
  const service = makeService();
  // second call
  service.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);
        let tree = parse(source);
        let provider = JsTsReceiverFactProvider::new(
            &analyzer,
            analyzer.definition_lookup_index(),
            Language::TypeScript,
            &file,
            source,
            tree.root_node(),
            ImportBinder::empty(),
        );
        let first = receiver_node(tree.root_node(), source, "first call", "service");
        let second = receiver_node(tree.root_node(), source, "second call", "service");
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 80,
            ..ReceiverAnalysisBudget::default()
        };

        for receiver in [first, second] {
            let outcome =
                provider.resolve_member_targets(receiver, "run", receiver.start_byte(), budget);
            assert!(
                matches!(outcome, ReceiverAnalysisOutcome::Precise(ref targets) if targets.len() == 1),
                "expected each lookup to stay within its own budget, got {outcome:?}"
            );
        }
    }

    #[test]
    fn fanout_over_default_target_cap_is_ambiguous() {
        let source = r#"
class A { run() {} }
class B { run() {} }
class C { run() {} }
class D { run() {} }
class E { run() {} }
function make(which: number) {
  if (which === 0) return new A();
  if (which === 1) return new B();
  if (which === 2) return new C();
  if (which === 3) return new D();
  return new E();
}
export function caller(which: number) {
  const service = make(which);
  service.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);
        let tree = parse(source);
        let provider = JsTsReceiverFactProvider::new(
            &analyzer,
            analyzer.definition_lookup_index(),
            Language::TypeScript,
            &file,
            source,
            tree.root_node(),
            ImportBinder::empty(),
        );
        let receiver = receiver_node(tree.root_node(), source, "service.run", "service");

        let outcome = provider.resolve_member_targets(
            receiver,
            "run",
            receiver.start_byte(),
            ReceiverAnalysisBudget::default(),
        );

        assert!(
            matches!(outcome, ReceiverAnalysisOutcome::Ambiguous(ref targets) if targets.len() > DEFAULT_RECEIVER_MAX_TARGETS),
            "expected fanout to become ambiguous, got {outcome:?}"
        );
        assert!(outcome.is_terminal_for_graph());
    }
}
