//! JavaScript / TypeScript receiver facts for bounded object-sensitive usage analysis.
//!
//! This provider intentionally starts with the small, structurally proven forms that
//! issue #394 needs first: local receivers assigned from `new Class()`, top-level
//! factory calls that return constructed values, and class factory methods whose body
//! returns a constructed value.

use super::extractor::slice;
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisBudgetTracker, ReceiverAnalysisOutcome,
    ReceiverAnalysisQuery, ReceiverFactProvider, ReceiverSummaryQuery, ReceiverValue,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::hash::{HashMap, HashSet};
use crate::profiling;
use tree_sitter::Node;

const MAX_JSTS_RECEIVER_RECURSION: usize = 8;

pub(crate) struct JsTsReceiverFactProvider<'tree, 'a> {
    analyzer: &'a dyn IAnalyzer,
    language: Language,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'tree>,
    function_declarations_by_name: HashMap<String, Vec<Node<'tree>>>,
    class_declarations_by_name: HashMap<String, Vec<Node<'tree>>>,
}

impl<'tree, 'a> JsTsReceiverFactProvider<'tree, 'a> {
    pub(crate) fn new(
        analyzer: &'a dyn IAnalyzer,
        language: Language,
        file: &'a ProjectFile,
        source: &'a str,
        root: Node<'tree>,
    ) -> Self {
        let (function_declarations_by_name, class_declarations_by_name) =
            index_js_ts_declarations(root, source);
        Self {
            analyzer,
            language,
            file,
            source,
            root,
            function_declarations_by_name,
            class_declarations_by_name,
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
        let mut tracker = ReceiverAnalysisBudgetTracker::new(budget);
        match self.resolve_expression(receiver, 0, budget, &mut tracker) {
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
        }
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
            "call_expression" => self.summarize_call_node(expression, depth + 1, budget, tracker),
            "identifier" | "type_identifier" => {
                let name = slice(expression, self.source);
                if name.is_empty() {
                    ReceiverAnalysisOutcome::Unknown
                } else {
                    self.resolve_identifier_binding(
                        name,
                        expression.start_byte(),
                        depth + 1,
                        budget,
                        tracker,
                    )
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
            .class_units_named(name)
            .into_iter()
            .map(|ty| ReceiverValue::AllocationSite {
                ty,
                file: self.file.clone(),
                range: node_range(expression),
            })
            .collect::<Vec<_>>();
        ReceiverAnalysisOutcome::single_precise_or_ambiguous(values, budget)
    }

    fn resolve_identifier_binding(
        &self,
        receiver: &str,
        before_byte: usize,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let scopes = lexical_scopes_for_byte(self.root, before_byte);
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
            if node.kind() == "variable_declarator"
                && let Some(name) = node.child_by_field_name("name")
                && node_text_matches(name, self.source, receiver)
            {
                latest = Some(
                    node.child_by_field_name("value")
                        .map(|value| self.resolve_expression(value, depth + 1, budget, tracker))
                        .unwrap_or(ReceiverAnalysisOutcome::Unknown),
                );
            } else if node.kind() == "assignment_expression"
                && let Some(left) = node.child_by_field_name("left")
                && matches!(left.kind(), "identifier" | "type_identifier")
                && node_text_matches(left, self.source, receiver)
            {
                latest = Some(
                    node.child_by_field_name("right")
                        .map(|right| self.resolve_expression(right, depth + 1, budget, tracker))
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

    fn resolve_static_object_expression(
        &self,
        expression: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let Some(name) = simple_identifier_text(expression, self.source) else {
            return ReceiverAnalysisOutcome::Unsupported {
                reason: "unsupported_static_factory_receiver",
            };
        };
        ReceiverAnalysisOutcome::single_precise_or_ambiguous(
            self.class_units_named(name)
                .into_iter()
                .map(ReceiverValue::ClassOrStaticObject),
            budget,
        )
    }

    fn summarize_call_node(
        &self,
        call: Node<'tree>,
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
                self.summarize_named_function(name, depth + 1, budget, tracker)
            }
            "member_expression" => self.summarize_member_call(function, depth + 1, budget, tracker),
            _ => ReceiverAnalysisOutcome::Unsupported {
                reason: "unsupported_call_callee",
            },
        }
    }

    fn summarize_named_function(
        &self,
        name: &str,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        if name.is_empty() {
            return ReceiverAnalysisOutcome::Unknown;
        }
        let functions = self.function_declarations_named(name);
        if functions.is_empty() {
            return ReceiverAnalysisOutcome::Unknown;
        }
        let outcomes: Vec<_> = functions
            .into_iter()
            .map(|function| self.summarize_function_body(function, depth + 1, budget, tracker))
            .collect();
        ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget)
    }

    fn summarize_member_call(
        &self,
        member_expression: Node<'tree>,
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
        let class_values = self.resolve_static_object_expression(object, budget);
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

    fn class_units_named(&self, name: &str) -> Vec<CodeUnit> {
        let mut units = self
            .analyzer
            .declarations(self.file)
            .filter(|unit| {
                unit.is_class()
                    && unit.identifier() == name
                    && crate::analyzer::common::language_for_file(unit.source()) == self.language
            })
            .cloned()
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
            .filter(|unit| unit.is_function())
            .cloned()
            .collect::<Vec<_>>();
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn function_declarations_named(&self, name: &str) -> Vec<Node<'tree>> {
        self.function_declarations_by_name
            .get(name)
            .cloned()
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
        self.summarize_call_node(node, 0, query.budget, &mut tracker)
    }
}

fn lexical_scopes_for_byte<'tree>(root: Node<'tree>, byte: usize) -> Vec<Node<'tree>> {
    let mut scopes = Vec::new();
    let Some(mut current) = smallest_named_node_covering(root, byte, byte) else {
        return scopes;
    };
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

fn is_scope_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
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
            Language::TypeScript,
            &file,
            source,
            tree.root_node(),
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
            Language::TypeScript,
            &file,
            source,
            tree.root_node(),
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
