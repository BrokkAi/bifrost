//! JavaScript / TypeScript receiver facts for bounded object-sensitive usage analysis.
//!
//! This provider intentionally starts with the small, structurally proven forms that
//! issue #394 needs first: local receivers assigned from `new Class()`, top-level
//! factory calls that return constructed values, and class factory methods whose body
//! returns a constructed value.

use crate::imports::require_call_module_specifier;
use crate::imports::{
    resolve_js_ts_direct_import_candidates, resolve_js_ts_module_binding_candidates,
};
use crate::providers::JsTsAnalyzerHost;
use crate::syntax::compute_import_binder as compute_jsts_import_binder;
use crate::syntax::parse_js_ts_tree;
use crate::syntax::{JsTsImportBinder, slice};
use crate::ts_owners::ts_resolve_type_text_to_property_owners;
use crate::tsconfig::AliasResolver;
use crate::type_text::ts_type_annotation_text;
use brokk_bifrost_core::analyzer::tree_walk::subtree_contains;
use brokk_bifrost_core::analyzer::tree_walk::{
    BoundedNamedTreeWalk, walk_named_tree_preorder_bounded,
};
use brokk_bifrost_core::analyzer::usages::model::ImportKind;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisBudgetTracker, ReceiverAnalysisCacheKey,
    ReceiverAnalysisOutcome, ReceiverAnalysisQuery, ReceiverAnalysisReport, ReceiverContext,
    ReceiverFactProvider, ReceiverFacts, ReceiverMemberTargetReport, ReceiverSummaryQuery,
    ReceiverValue,
};
use brokk_bifrost_core::analyzer::usages::reference_site::{
    node_range, smallest_named_node_covering,
};
use brokk_bifrost_core::analyzer::{
    BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, Language, ProjectFile,
};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::profiling;
use std::cell::RefCell;
use std::sync::Arc;
use tree_sitter::Node;

const MAX_JSTS_RECEIVER_RECURSION: usize = 8;

pub struct JsTsReceiverFactProvider<'tree, 'a> {
    host: &'a dyn JsTsAnalyzerHost,
    support: &'a dyn BoundedDefinitionLookup,
    language: Language,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'tree>,
    imports: JsTsImportBinder,
    aliases: Arc<AliasResolver>,
    syntax_index: Arc<JsTsReceiverSyntaxIndex>,
    member_target_cache:
        RefCell<HashMap<ReceiverAnalysisCacheKey, ReceiverAnalysisOutcome<CodeUnit>>>,
    jsx_props_owner_cache: RefCell<HashMap<(ProjectFile, String), Vec<CodeUnit>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexedNodeRange {
    start_byte: usize,
    end_byte: usize,
}

#[derive(Debug, Default)]
pub struct JsTsReceiverSyntaxIndex {
    function_declarations_by_name: HashMap<String, Vec<IndexedNodeRange>>,
    class_declarations_by_name: HashMap<String, Vec<IndexedNodeRange>>,
}

pub enum JsTsReceiverSyntaxIndexBuild {
    Complete {
        index: Arc<JsTsReceiverSyntaxIndex>,
        visited: usize,
    },
    ExceededScope {
        visited: usize,
    },
    Cancelled,
}

impl<'tree, 'a> JsTsReceiverFactProvider<'tree, 'a> {
    pub fn new(
        host: &'a dyn JsTsAnalyzerHost,
        support: &'a dyn BoundedDefinitionLookup,
        language: Language,
        file: &'a ProjectFile,
        source: &'a str,
        root: Node<'tree>,
        imports: JsTsImportBinder,
    ) -> Self {
        let (syntax_index, _) =
            build_js_ts_receiver_syntax_index(root, source, None).expect("uncancelled index build");
        Self::new_with_syntax_index(
            host,
            support,
            language,
            file,
            source,
            root,
            imports,
            syntax_index,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_syntax_index(
        host: &'a dyn JsTsAnalyzerHost,
        support: &'a dyn BoundedDefinitionLookup,
        language: Language,
        file: &'a ProjectFile,
        source: &'a str,
        root: Node<'tree>,
        imports: JsTsImportBinder,
        syntax_index: Arc<JsTsReceiverSyntaxIndex>,
    ) -> Self {
        Self::new_with_batch_data(
            host,
            support,
            language,
            file,
            source,
            root,
            imports,
            Arc::new(AliasResolver::new(host.project().root().to_path_buf())),
            syntax_index,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_batch_data(
        host: &'a dyn JsTsAnalyzerHost,
        support: &'a dyn BoundedDefinitionLookup,
        language: Language,
        file: &'a ProjectFile,
        source: &'a str,
        root: Node<'tree>,
        imports: JsTsImportBinder,
        aliases: Arc<AliasResolver>,
        syntax_index: Arc<JsTsReceiverSyntaxIndex>,
    ) -> Self {
        Self {
            host,
            support,
            language,
            file,
            source,
            root,
            imports,
            aliases,
            syntax_index,
            member_target_cache: RefCell::new(HashMap::default()),
            jsx_props_owner_cache: RefCell::new(HashMap::default()),
        }
    }

    pub fn resolve_receiver_node(
        &self,
        node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        self.resolve_receiver_node_report(node, budget).outcome
    }

    pub fn resolve_receiver_node_report(
        &self,
        node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisReport<ReceiverValue> {
        let _scope = profiling::scope("jsts.receiver_analysis.resolve_receiver_node");
        let mut tracker = ReceiverAnalysisBudgetTracker::new(budget);
        let outcome = self.resolve_expression(node, 0, budget, &mut tracker);
        tracker.report(outcome)
    }

    pub fn resolve_iterable_element(
        &self,
        node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        if self.language != Language::TypeScript {
            return ReceiverAnalysisOutcome::Unknown;
        }
        let Some(name) = matches!(node.kind(), "identifier" | "type_identifier")
            .then(|| slice(node, self.source))
            .filter(|name| !name.is_empty())
        else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let mut tracker = ReceiverAnalysisBudgetTracker::new(budget);
        for scope in lexical_scopes_for_node(node) {
            if let Some(outcome) = self.latest_iterable_element_binding_in_scope(
                scope,
                name,
                node.start_byte(),
                budget,
                &mut tracker,
            ) {
                return outcome;
            }
        }
        ReceiverAnalysisOutcome::Unknown
    }

    pub fn resolve_member_targets(
        &self,
        receiver: Node<'tree>,
        member: &str,
        _before_byte: usize,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<CodeUnit> {
        self.resolve_member_targets_report(receiver, member, _before_byte, budget)
            .outcome
    }

    pub fn resolve_member_targets_report(
        &self,
        receiver: Node<'tree>,
        member: &str,
        _before_byte: usize,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisReport<CodeUnit> {
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
            return ReceiverAnalysisReport::without_work(cached, budget);
        }
        let mut tracker = ReceiverAnalysisBudgetTracker::new(budget);
        let outcome = match self.resolve_expression(receiver, 0, budget, &mut tracker) {
            ReceiverAnalysisOutcome::Precise(values) => {
                let targets = values
                    .iter()
                    .flat_map(|value| self.member_targets_for_value(value, member))
                    .collect::<Vec<_>>();
                ReceiverAnalysisOutcome::single_precise_or_ambiguous(targets, budget)
            }
            ReceiverAnalysisOutcome::Ambiguous(values) => {
                let targets = values
                    .iter()
                    .flat_map(|value| self.member_targets_for_value(value, member))
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
        tracker.report(outcome)
    }

    pub fn resolve_member_targets_at_site(
        &self,
        site: Node<'tree>,
        expected_member: Option<&str>,
        before_byte: usize,
        budget: ReceiverAnalysisBudget,
    ) -> Option<ReceiverMemberTargetReport> {
        let member_expression = member_expression_at_site(site)?;
        let property = member_expression.child_by_field_name("property")?;
        let member_name = slice(property, self.source);
        if member_name.is_empty() || expected_member.is_some_and(|expected| expected != member_name)
        {
            return None;
        }
        let receiver = member_expression.child_by_field_name("object")?;
        Some(ReceiverMemberTargetReport {
            receiver_range: node_range(receiver),
            member_name: member_name.to_string(),
            analysis: self.resolve_member_targets_report(
                receiver,
                member_name,
                before_byte,
                budget,
            ),
        })
    }

    pub fn resolve_contextual_object_literal_key_targets(
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
            .flat_map(|value| self.member_targets_for_value(value, &member))
            .collect::<Vec<_>>();
        sort_units(&mut targets);
        targets.dedup();
        targets.truncate(budget.max_targets.saturating_add(1));
        targets
    }

    /// Resolves a JSX attribute name through the element's component declaration to
    /// the exact field on its props type. `None` means `node` is not an attribute
    /// name; `Some([])` is a recognized attribute whose owner cannot be proven.
    pub fn resolve_jsx_attribute_targets(
        &self,
        node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> Option<Vec<CodeUnit>> {
        let (attribute_name, element_name) = jsx_attribute_site(node)?;
        if self.language != Language::TypeScript {
            return Some(Vec::new());
        }
        let attribute = slice(attribute_name, self.source);
        let Some(component) = simple_identifier_text(element_name, self.source)
            .filter(|name| name.starts_with(|ch: char| ch.is_ascii_uppercase()))
        else {
            return Some(Vec::new());
        };

        let components = self.jsx_component_candidates(component);
        let mut targets = components
            .iter()
            .flat_map(|component| self.jsx_component_prop_owners(component))
            .flat_map(|owner| self.member_targets(&owner, attribute))
            .collect::<Vec<_>>();
        sort_units(&mut targets);
        targets.dedup();
        targets.truncate(budget.max_targets.saturating_add(1));
        Some(targets)
    }

    fn jsx_component_candidates(&self, name: &str) -> Vec<CodeUnit> {
        let mut candidates = resolve_js_ts_direct_import_candidates(
            self.host,
            self.support,
            self.language,
            self.file,
            &self.imports,
            name,
            Some(&self.aliases),
            true,
        )
        .unwrap_or_else(|| {
            self.support
                .file_identifier(self.file, name)
                .into_iter()
                .filter(|unit| unit.source() == self.file)
                .collect()
        });
        candidates.retain(|unit| unit.is_function() || unit.is_field() || unit.is_class());
        sort_units(&mut candidates);
        candidates.dedup();
        candidates
    }

    fn jsx_component_prop_owners(&self, component: &CodeUnit) -> Vec<CodeUnit> {
        let cache_key = (component.source().clone(), component.fq_name());
        if let Some(cached) = self.jsx_props_owner_cache.borrow().get(&cache_key) {
            return cached.clone();
        }
        let Ok(source) = component.source().read_to_string() else {
            return Vec::new();
        };
        let Some(tree) = parse_js_ts_tree(component.source(), &source, Language::TypeScript) else {
            return Vec::new();
        };
        let imports = compute_jsts_import_binder(&source, &tree);
        let aliases = AliasResolver::new(self.host.project().root().to_path_buf());
        let mut owners = nodes_for_code_unit(self.host, component, tree.root_node())
            .into_iter()
            .filter_map(|node| jsx_component_props_type(node, component.identifier(), &source))
            .flat_map(|type_node| {
                ts_resolve_type_text_to_property_owners(
                    self.host,
                    self.support,
                    component.source(),
                    &source,
                    &imports,
                    &aliases,
                    ts_type_annotation_text(type_node, &source).as_str(),
                    0,
                )
            })
            .collect::<Vec<_>>();
        sort_units(&mut owners);
        owners.dedup();
        self.jsx_props_owner_cache
            .borrow_mut()
            .insert(cache_key, owners.clone());
        owners
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
        let mut current = receiver_node;
        loop {
            if is_scope_boundary(current.kind())
                && let Some(outcome) = self.latest_identifier_binding_in_scope(
                    current,
                    receiver,
                    before_byte,
                    depth,
                    budget,
                    tracker,
                )
            {
                return outcome;
            }
            let Some(parent) = current.parent() else {
                break;
            };
            current = parent;
        }
        ReceiverAnalysisOutcome::Unknown
    }

    fn latest_iterable_element_binding_in_scope(
        &self,
        scope: Node<'tree>,
        receiver: &str,
        before_byte: usize,
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
            if matches!(node.kind(), "required_parameter" | "optional_parameter")
                && node
                    .child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("pattern"))
                    .is_some_and(|name| node_text_matches(name, self.source, receiver))
                && let Some(type_node) = node.child_by_field_name("type")
            {
                latest = Some(self.iterable_element_type_outcome(type_node, budget));
            } else if binding_node_shadows_receiver(node, self.source, receiver) {
                latest = Some(ReceiverAnalysisOutcome::Unknown);
            } else if node.kind() == "variable_declarator"
                && let Some(name) = node.child_by_field_name("name")
                && node_text_matches(name, self.source, receiver)
            {
                latest = Some(
                    node.child_by_field_name("type")
                        .map(|type_node| self.iterable_element_type_outcome(type_node, budget))
                        .unwrap_or(ReceiverAnalysisOutcome::Unknown),
                );
            }

            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
        latest
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
            self.host,
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

    fn iterable_element_type_outcome(
        &self,
        type_node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let values = iterable_element_type(type_node, self.source)
            .map(|element_type| self.type_annotation_receiver_values(element_type, budget))
            .unwrap_or_default();
        if values.is_empty() {
            ReceiverAnalysisOutcome::Unknown
        } else {
            ReceiverAnalysisOutcome::single_precise_or_ambiguous(values, budget)
        }
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
            .filter_map(|function| {
                let factory = self.function_unit_for_node(name, function)?;
                Some(wrap_factory_outcome(
                    self.summarize_function_body(function, depth + 1, budget, tracker),
                    &factory,
                ))
            })
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
        let functions = resolve_js_ts_direct_import_candidates(
            self.host,
            self.support,
            self.language,
            self.file,
            &self.imports,
            name,
            Some(&self.aliases),
            true,
        )?
        .into_iter()
        .filter(|unit| unit.is_function())
        .collect::<Vec<_>>();
        if functions.is_empty() {
            return None;
        }

        self.summarize_external_functions(functions, depth, budget, tracker)
    }

    fn summarize_external_functions(
        &self,
        functions: Vec<CodeUnit>,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> Option<ReceiverAnalysisOutcome<ReceiverValue>> {
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
                self.host,
                self.support,
                self.language,
                function.source(),
                &source,
                tree.root_node(),
                imports,
            );
            for node in nodes_for_code_unit(self.host, &function, tree.root_node()) {
                outcomes.push(wrap_factory_outcome(
                    provider.summarize_function_body(node, depth + 1, budget, tracker),
                    &function,
                ));
            }
        }
        (!outcomes.is_empty())
            .then(|| ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget))
    }

    fn summarize_module_member_function(
        &self,
        object: Node<'tree>,
        member: &str,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> Option<ReceiverAnalysisOutcome<ReceiverValue>> {
        if self.language != Language::JavaScript {
            return None;
        }
        let module_specifier =
            require_call_module_specifier(object, self.source).or_else(|| {
                let binding_name = simple_identifier_text(object, self.source)?;
                let binding = self.imports.binding(binding_name)?;
                matches!(
                    binding.kind,
                    ImportKind::Namespace | ImportKind::CommonJsRequire
                )
                .then(|| binding.module_specifier.clone())
            })?;
        let functions = resolve_js_ts_module_binding_candidates(
            self.host,
            self.support,
            self.language,
            self.file,
            &module_specifier,
            member,
            Some(&self.aliases),
            true,
        )
        .into_iter()
        .filter(|unit| unit.is_function())
        .collect::<Vec<_>>();
        self.summarize_external_functions(functions, depth, budget, tracker)
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
        if let Some(outcome) =
            self.summarize_module_member_function(object, member, depth + 1, budget, tracker)
        {
            return outcome;
        }
        let class_values = self.resolve_static_object_expression(object, call_byte, budget);
        let ReceiverAnalysisOutcome::Precise(values) = class_values else {
            return class_values;
        };
        let mut methods = Vec::new();
        for value in values {
            for factory in self.member_targets_for_value(&value, member) {
                methods.extend(
                    nodes_for_code_unit(self.host, &factory, self.root)
                        .into_iter()
                        .map(|node| (node, factory.clone())),
                );
            }
        }
        if methods.is_empty() {
            return ReceiverAnalysisOutcome::Unknown;
        }
        let outcomes: Vec<_> = methods
            .into_iter()
            .map(|(method, factory)| {
                wrap_factory_outcome(
                    self.summarize_function_body(method, depth + 1, budget, tracker),
                    &factory,
                )
            })
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
            .host
            .declarations(self.file)
            .into_iter()
            .filter(|unit| {
                unit.is_class()
                    && unit.identifier() == name
                    && brokk_bifrost_core::analyzer::common::language_for_file(unit.source())
                        == self.language
            })
            .collect::<Vec<_>>();
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn member_targets(&self, owner: &CodeUnit, member: &str) -> Vec<CodeUnit> {
        let fqn = format!("{}.{}", owner.fq_name(), member);
        let mut units = self
            .host
            .definitions(&fqn)
            .filter(|unit| unit.source() == owner.source())
            .filter(|unit| unit.is_function() || unit.is_field())
            .collect::<Vec<_>>();
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn member_targets_for_value(&self, receiver: &ReceiverValue, member: &str) -> Vec<CodeUnit> {
        let indexed_member = if matches!(receiver, ReceiverValue::ClassOrStaticObject(_)) {
            format!("{member}$static")
        } else {
            member.to_string()
        };
        self.member_targets(receiver.owner(), &indexed_member)
    }

    fn visible_function_declarations_named(
        &self,
        name: &str,
        site: Node<'tree>,
    ) -> Vec<Node<'tree>> {
        let visible_scopes = lexical_scope_ids_for_node(site);
        self.syntax_index
            .function_declarations_by_name
            .get(name)
            .map(|functions| {
                functions
                    .iter()
                    .filter_map(|range| {
                        smallest_named_node_covering(self.root, range.start_byte, range.end_byte)
                    })
                    .filter(|function| {
                        declaration_scope_id(*function)
                            .is_some_and(|id| visible_scopes.contains(&id))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn function_unit_for_node(&self, name: &str, node: Node<'_>) -> Option<CodeUnit> {
        let target = IndexedNodeRange {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
        };
        let syntax_ranges = self.syntax_index.function_declarations_by_name.get(name)?;
        self.support
            .file_identifier(self.file, name)
            .into_iter()
            .filter(|unit| unit.source() == self.file && unit.is_function())
            .filter_map(|unit| {
                let associated_syntax = self
                    .host
                    .ranges(&unit)
                    .into_iter()
                    .flat_map(|declaration_range| {
                        syntax_ranges
                            .iter()
                            .filter(move |syntax_range| {
                                declaration_range.start_byte < syntax_range.end_byte
                                    && syntax_range.start_byte < declaration_range.end_byte
                            })
                            .map(move |syntax_range| {
                                let boundary_distance = declaration_range
                                    .start_byte
                                    .abs_diff(syntax_range.start_byte)
                                    .saturating_add(
                                        declaration_range.end_byte.abs_diff(syntax_range.end_byte),
                                    );
                                let span_distance = declaration_range
                                    .end_byte
                                    .saturating_sub(declaration_range.start_byte)
                                    .abs_diff(
                                        syntax_range
                                            .end_byte
                                            .saturating_sub(syntax_range.start_byte),
                                    );
                                (boundary_distance, span_distance, *syntax_range)
                            })
                    })
                    .min_by_key(|(boundary_distance, span_distance, syntax_range)| {
                        (*boundary_distance, *span_distance, syntax_range.start_byte)
                    })?
                    .2;
                (associated_syntax == target).then_some(unit)
            })
            .min()
    }

    fn visible_class_declaration_nodes(&self, name: &str, site: Node<'tree>) -> Vec<Node<'tree>> {
        let visible_scopes = lexical_scope_ids_for_node(site);
        self.syntax_index
            .class_declarations_by_name
            .get(name)
            .map(|classes| {
                classes
                    .iter()
                    .filter_map(|range| {
                        smallest_named_node_covering(self.root, range.start_byte, range.end_byte)
                    })
                    .filter(|class| {
                        declaration_scope_id(*class).is_some_and(|id| visible_scopes.contains(&id))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn jsx_attribute_site(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let attribute = if node.kind() == "jsx_attribute" {
        node
    } else {
        node.parent()
            .filter(|parent| parent.kind() == "jsx_attribute")?
    };
    let attribute_name = attribute.named_child(0)?;
    if attribute_name.id() != node.id() && node.kind() != "jsx_attribute" {
        return None;
    }
    if attribute_name.kind() != "property_identifier" {
        return None;
    }
    let element = attribute.parent().filter(|parent| {
        matches!(
            parent.kind(),
            "jsx_opening_element" | "jsx_self_closing_element"
        )
    })?;
    Some((attribute_name, element.child_by_field_name("name")?))
}

fn jsx_component_props_type<'tree>(
    node: Node<'tree>,
    component_name: &str,
    source: &str,
) -> Option<Node<'tree>> {
    let declaration = enclosing_component_declaration(node, component_name, source)?;
    match declaration.kind() {
        "function_declaration" | "function_expression" | "arrow_function" => {
            function_first_parameter_type(declaration)
        }
        "variable_declarator" => declaration
            .child_by_field_name("value")
            .filter(|value| matches!(value.kind(), "function_expression" | "arrow_function"))
            .and_then(function_first_parameter_type)
            .or_else(|| {
                declaration
                    .child_by_field_name("type")
                    .and_then(|node| function_component_wrapper_argument(node, source))
            }),
        "class_declaration" | "abstract_class_declaration" => {
            class_component_props_argument(declaration, source)
        }
        _ => None,
    }
}

fn enclosing_component_declaration<'tree>(
    node: Node<'tree>,
    component_name: &str,
    source: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![node];
    while let Some(candidate) = stack.pop() {
        if component_declaration_has_name(candidate, component_name, source) {
            return Some(candidate);
        }
        for index in (0..candidate.named_child_count()).rev() {
            if let Some(child) = candidate.named_child(index) {
                stack.push(child);
            }
        }
    }

    let mut current = Some(node);
    while let Some(candidate) = current {
        if component_declaration_has_name(candidate, component_name, source) {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn component_declaration_has_name(node: Node<'_>, component_name: &str, source: &str) -> bool {
    matches!(
        node.kind(),
        "function_declaration"
            | "class_declaration"
            | "abstract_class_declaration"
            | "variable_declarator"
    ) && node
        .child_by_field_name("name")
        .is_some_and(|name| node_text_matches(name, source, component_name))
}

fn function_first_parameter_type(function: Node<'_>) -> Option<Node<'_>> {
    let parameters = function.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .next()
        .and_then(|parameter| parameter.child_by_field_name("type"))
}

fn function_component_wrapper_argument<'tree>(
    type_annotation: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![type_annotation];
    while let Some(node) = stack.pop() {
        if node.kind() == "generic_type" {
            let Some(terminal) = node
                .child_by_field_name("name")
                .and_then(|name| type_reference_terminal(name, source))
            else {
                continue;
            };
            if matches!(terminal, "FC" | "FunctionComponent" | "ComponentType") {
                return node
                    .child_by_field_name("type_arguments")
                    .and_then(|arguments| arguments.named_child(0));
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

fn class_component_props_argument<'tree>(class: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let mut cursor = class.walk();
    let heritage = class
        .named_children(&mut cursor)
        .find(|child| child.kind() == "class_heritage")?;
    let mut cursor = heritage.walk();
    for extends in heritage
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "extends_clause")
    {
        let value = extends.child_by_field_name("value")?;
        let terminal = type_reference_terminal(value, source)?;
        if matches!(terminal, "Component" | "PureComponent") {
            return extends
                .child_by_field_name("type_arguments")
                .and_then(|arguments| arguments.named_child(0));
        }
    }
    None
}

fn type_reference_terminal<'a>(mut node: Node<'_>, source: &'a str) -> Option<&'a str> {
    loop {
        if let Some(name) = node.child_by_field_name("name")
            && name.id() != node.id()
        {
            node = name;
            continue;
        }
        return match node.kind() {
            "identifier" | "type_identifier" | "property_identifier" => {
                let text = slice(node, source);
                (!text.is_empty()).then_some(text)
            }
            _ => None,
        };
    }
}

impl<'tree> ReceiverFacts<'tree> for JsTsReceiverFactProvider<'tree, '_> {
    fn member_expression_at_site(&self, node: Node<'tree>) -> Option<Node<'tree>> {
        member_expression_at_site(node)
    }

    fn resolve_receiver(
        &self,
        node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisReport<ReceiverValue> {
        self.resolve_receiver_node_report(node, budget)
    }

    fn resolve_member_targets_at_site(
        &self,
        site: Node<'tree>,
        expected_member: Option<&str>,
        before_byte: usize,
        budget: ReceiverAnalysisBudget,
    ) -> Option<ReceiverMemberTargetReport> {
        JsTsReceiverFactProvider::resolve_member_targets_at_site(
            self,
            site,
            expected_member,
            before_byte,
            budget,
        )
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

fn iterable_element_type<'tree>(type_node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let mut type_node = if type_node.kind() == "type_annotation" {
        type_node.named_child(0)?
    } else {
        type_node
    };
    loop {
        match type_node.kind() {
            "array_type" => return type_node.named_child(0),
            "generic_type" => {
                let name = type_node.child_by_field_name("name")?;
                if !matches!(
                    slice(name, source),
                    "Array"
                        | "ReadonlyArray"
                        | "Set"
                        | "ReadonlySet"
                        | "Iterable"
                        | "AsyncIterable"
                ) {
                    return None;
                }
                return type_node
                    .child_by_field_name("type_arguments")
                    .and_then(|arguments| arguments.named_child(0));
            }
            "parenthesized_type" | "readonly_type" => type_node = type_node.named_child(0)?,
            _ => return None,
        }
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
    let member = crate::typescript::ts_object_literal_property_name(property, source)?;
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
    subtree_contains(node, |node| {
        matches!(
            node.kind(),
            "identifier" | "type_identifier" | "shorthand_property_identifier_pattern"
        ) && node_text_matches(node, source, receiver)
    })
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

fn nodes_for_code_unit<'tree>(
    unit_index: &dyn CodeUnitIndex,
    unit: &CodeUnit,
    root: Node<'tree>,
) -> Vec<Node<'tree>> {
    unit_index
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

pub fn build_js_ts_receiver_syntax_index<'tree>(
    root: Node<'tree>,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<(Arc<JsTsReceiverSyntaxIndex>, usize)> {
    match build_js_ts_receiver_syntax_index_bounded(root, source, cancellation, usize::MAX) {
        JsTsReceiverSyntaxIndexBuild::Complete { index, visited } => Some((index, visited)),
        JsTsReceiverSyntaxIndexBuild::Cancelled => None,
        JsTsReceiverSyntaxIndexBuild::ExceededScope { .. } => {
            unreachable!("an in-memory syntax tree cannot exceed usize::MAX nodes")
        }
    }
}

pub fn build_js_ts_receiver_syntax_index_bounded<'tree>(
    root: Node<'tree>,
    source: &str,
    cancellation: Option<&CancellationToken>,
    max_scope_nodes: usize,
) -> JsTsReceiverSyntaxIndexBuild {
    let mut functions: HashMap<String, Vec<IndexedNodeRange>> = HashMap::default();
    let mut classes: HashMap<String, Vec<IndexedNodeRange>> = HashMap::default();
    let traversal =
        walk_named_tree_preorder_bounded(root, true, max_scope_nodes, cancellation, |node| {
            let range = IndexedNodeRange {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
            };
            if node.kind() == "function_declaration"
                && let Some(name_node) = node.child_by_field_name("name")
                && let Some(name) = simple_identifier_text(name_node, source)
            {
                functions.entry(name.to_string()).or_default().push(range);
            } else if matches!(
                node.kind(),
                "class_declaration" | "abstract_class_declaration"
            ) && let Some(name_node) = node.child_by_field_name("name")
                && let Some(name) = simple_identifier_text(name_node, source)
            {
                classes.entry(name.to_string()).or_default().push(range);
            }
        });
    let visited = match traversal {
        BoundedNamedTreeWalk::Complete { visited } => visited,
        BoundedNamedTreeWalk::Exceeded { visited } => {
            return JsTsReceiverSyntaxIndexBuild::ExceededScope { visited };
        }
        BoundedNamedTreeWalk::Cancelled => return JsTsReceiverSyntaxIndexBuild::Cancelled,
    };
    JsTsReceiverSyntaxIndexBuild::Complete {
        index: Arc::new(JsTsReceiverSyntaxIndex {
            function_declarations_by_name: functions,
            class_declarations_by_name: classes,
        }),
        visited,
    }
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

fn wrap_factory_outcome(
    outcome: ReceiverAnalysisOutcome<ReceiverValue>,
    factory: &CodeUnit,
) -> ReceiverAnalysisOutcome<ReceiverValue> {
    let wrap = |value| ReceiverValue::FactoryReturn {
        factory: factory.clone(),
        value: Box::new(value),
    };
    match outcome {
        ReceiverAnalysisOutcome::Precise(values) => {
            ReceiverAnalysisOutcome::Precise(values.into_iter().map(wrap).collect())
        }
        ReceiverAnalysisOutcome::Ambiguous(values) => {
            ReceiverAnalysisOutcome::Ambiguous(values.into_iter().map(wrap).collect())
        }
        ReceiverAnalysisOutcome::Unknown => ReceiverAnalysisOutcome::Unknown,
        ReceiverAnalysisOutcome::Unsupported { reason } => {
            ReceiverAnalysisOutcome::Unsupported { reason }
        }
        ReceiverAnalysisOutcome::ExceededBudget { limit } => {
            ReceiverAnalysisOutcome::ExceededBudget { limit }
        }
    }
}

pub fn member_expression_at_site(mut node: Node<'_>) -> Option<Node<'_>> {
    for _ in 0..4 {
        if node.kind() == "member_expression" {
            return Some(node);
        }
        if node.kind() == "call_expression"
            && let Some(function) = node.child_by_field_name("function")
            && function.kind() == "member_expression"
        {
            return Some(function);
        }
        node = node.parent()?;
    }
    None
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
