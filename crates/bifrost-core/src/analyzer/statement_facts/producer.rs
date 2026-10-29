//! Query-local statement aggregation over normalized syntax and language roles.

use super::{
    ConditionFact, EnumFact, EnumeratorFact, GotoFact, LabelFact, LoopFact, StatementFact,
    StatementFactKind, StatementFactRows, SwitchCaseFact, SwitchFact,
};
use crate::analyzer::structural::body_relations::{BodyState, BodyStateAnswer, body_state};
use crate::analyzer::structural::conditional_regions::ConditionalRegions;
use crate::analyzer::structural::{
    kinds::{NormalizedKind, Role},
    spec::StructuralSpec,
};
use crate::analyzer::tree_walk::{
    named_children_iter, node_range, unwrap_parenthesized_expression,
};
use crate::hash::{HashMap, HashSet};
use tree_sitter::Node;

/// Grammar and binding evidence that normalized kinds cannot supply. No
/// thresholds, containment searches, or aggregate classification live here.
pub trait StatementFactSyntax: Sync {
    /// A grammar hook need not supply every statement-fact kind.
    fn supports_kind(&self, _kind: StatementFactKind) -> bool {
        true
    }
    /// AST fields carrying each normalized role, including wrapper handling.
    fn roles<'tree>(&self, node: Node<'tree>, role: Role) -> Vec<Node<'tree>>;
    /// Preprocessor directives and grammar extras are not executable children.
    fn is_code_child(&self, node: Node<'_>) -> bool {
        !node.is_extra()
    }
    /// The induction variable is a binder or assignment target, not a node kind.
    fn loop_variable(&self, node: Node<'_>, source: &str) -> Option<String>;
    /// Counted-loop grammar and initializer fields differ between languages.
    fn is_counted_loop(&self, node: Node<'_>) -> bool;
    /// Every initializer in source order, including repeated grammar fields.
    fn loop_initializers<'tree>(&self, node: Node<'tree>) -> Vec<Node<'tree>>;
    /// Only C/C++ has stack-allocation calls and goto statements.
    fn is_alloca(&self, _node: Node<'_>, _source: &str) -> bool {
        false
    }
    /// Resolve the switch operand's enum declaration using language binding rules.
    fn switch_enum<'tree>(&self, node: Node<'tree>, source: &str) -> Option<Node<'tree>>;
    /// Enum declarations/constants are not distinguished by normalized kinds.
    fn enumeration(&self, node: Node<'_>, source: &str) -> Option<(EnumFact, Vec<EnumeratorFact>)>;
    /// Select a terminal expression name (qualified identifiers differ by grammar).
    fn name<'tree>(&self, node: Node<'tree>) -> Option<Node<'tree>>;
}

struct JumpSites<'source> {
    labels: Vec<(&'source str, usize)>,
    gotos: Vec<(&'source str, usize)>,
}

pub struct StatementFacts<'a> {
    spec: &'a dyn StructuralSpec,
    syntax: &'a dyn StatementFactSyntax,
}

impl<'a> StatementFacts<'a> {
    pub fn new(spec: &'a dyn StructuralSpec) -> Option<Self> {
        Some(Self {
            spec,
            syntax: spec.statement_fact_syntax()?,
        })
    }

    fn kind(&self, node: Node<'_>) -> Option<NormalizedKind> {
        self.spec.kind_table().iter().find_map(|(name, kind)| {
            (*name == node.kind() && self.spec.should_extract(node, *kind)).then_some(*kind)
        })
    }

    fn is(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        self.kind(node).is_some_and(|actual| actual.satisfies(kind))
    }

    fn callable(&self, node: Node<'_>) -> bool {
        matches!(
            self.kind(node),
            Some(
                NormalizedKind::Function
                    | NormalizedKind::Method
                    | NormalizedKind::Constructor
                    | NormalizedKind::Lambda
            )
        )
    }

    fn role<'tree>(&self, node: Node<'tree>, role: Role) -> Option<Node<'tree>> {
        self.syntax.roles(node, role).into_iter().next()
    }

    fn children<'tree>(
        &'tree self,
        node: Node<'tree>,
    ) -> impl Iterator<Item = Node<'tree>> + 'tree {
        named_children_iter(node).filter(move |child| self.syntax.is_code_child(*child))
    }

    fn child_count(&self, node: Node<'_>) -> usize {
        self.children(node).count()
    }

    fn complex_statement_count(&self, block: Node<'_>) -> usize {
        self.children(block)
            .filter(|child| {
                self.is(*child, NormalizedKind::Switch)
                    || (self.is(*child, NormalizedKind::Loop)
                        && self
                            .role(*child, Role::Body)
                            .is_some_and(|body| self.child_count(body) > 6))
            })
            .count()
    }

    fn operator(&self, node: Node<'_>) -> Option<&'static str> {
        Some(self.role(node, Role::Operator)?.kind())
    }

    fn logical_operator(&self, node: Node<'_>) -> Option<&'static str> {
        self.operator(node)
            .filter(|operator| matches!(*operator, "&&" | "||"))
    }

    pub fn logical_operator_count(&self, expression: Node<'_>) -> usize {
        let mut count = 0usize;
        let mut stack = vec![expression];
        while let Some(node) = stack.pop() {
            if let Some(operator) = self.logical_operator(node) {
                let parent_operator = node
                    .parent()
                    .and_then(|parent| self.logical_operator(parent));
                if parent_operator != Some(operator) {
                    count = count.saturating_add(1);
                }
            }
            stack.extend(named_children_iter(node).filter(|child| !child.is_extra()));
        }
        count
    }

    fn cases<'tree>(&self, body: Node<'tree>) -> Vec<Node<'tree>> {
        let mut cases = Vec::new();
        let mut stack = vec![body];
        while let Some(node) = stack.pop() {
            if node != body && (self.is(node, NormalizedKind::Switch) || self.callable(node)) {
                continue;
            }
            if node != body && self.is(node, NormalizedKind::Case) {
                cases.push(node);
            }
            stack.extend(named_children_iter(node).filter(|child| !child.is_extra()));
        }
        cases.sort_unstable_by_key(Node::start_byte);
        cases
    }

    fn switch_cases<'tree>(&self, switch: Node<'tree>) -> Vec<Node<'tree>> {
        self.role(switch, Role::Body)
            .map(|body| self.cases(body))
            .unwrap_or_default()
    }

    fn long_case(&self, switch: Node<'_>, cases: &[Node<'_>]) -> bool {
        cases.iter().enumerate().any(|(index, case)| {
            let end = cases
                .get(index + 1)
                .map_or(switch.end_position().row + 1, |next| {
                    next.start_position().row + 1
                });
            end.saturating_sub(case.start_position().row + 1) > 30
        })
    }

    fn default_present(&self, cases: &[Node<'_>]) -> bool {
        cases
            .iter()
            .any(|case| self.syntax.roles(*case, Role::Test).is_empty())
    }

    fn missing_case(&self, switch: Node<'_>, cases: &[Node<'_>], source: &str) -> bool {
        let Some(enum_node) = self.syntax.switch_enum(switch, source) else {
            return false;
        };
        self.enum_missing_case(enum_node, cases, source)
    }

    fn enum_missing_case(&self, enum_node: Node<'_>, cases: &[Node<'_>], source: &str) -> bool {
        if self.default_present(cases) {
            return false;
        }
        let Some((_, enumerators)) = self.syntax.enumeration(enum_node, source) else {
            return false;
        };
        let declared: HashSet<_> = enumerators.iter().map(|item| item.name.as_str()).collect();
        let values: HashSet<_> = cases
            .iter()
            .flat_map(|case| self.syntax.roles(*case, Role::Test))
            .filter_map(|value| self.syntax.name(value))
            .filter_map(|name| name.utf8_text(source.as_bytes()).ok())
            .collect();
        !values.is_empty()
            && values.iter().all(|name| declared.contains(name))
            && declared.iter().any(|name| !values.contains(name))
    }

    /// Apply an analyzer-proven enum binding using the same completeness rule
    /// as grammar-local enum bindings. This does not infer a binding by name.
    pub fn complete_enum_switch(
        &self,
        switch: Node<'_>,
        enumeration: Node<'_>,
        source: &str,
        rows: &mut StatementFactRows,
    ) {
        if !self.enum_missing_case(enumeration, &self.switch_cases(switch), source) {
            return;
        }
        let range = node_range(switch);
        let fact = rows
            .switches
            .iter_mut()
            .find(|fact| fact.range == range)
            .expect("captured switch");
        fact.missing_enum_case = true;
        if !rows
            .statements
            .iter()
            .any(|fact| fact.range == range && fact.kind == StatementFactKind::MissingCaseInSwitch)
        {
            rows.statements.push(StatementFact {
                range,
                kind: StatementFactKind::MissingCaseInSwitch,
            });
        }
    }

    pub fn tightly_bounded(&self, loop_node: Node<'_>, source: &str) -> bool {
        let Some(variable) = self.syntax.loop_variable(loop_node, source) else {
            return false;
        };
        let Some(condition) = self.role(loop_node, Role::Test) else {
            return false;
        };
        let mut stack = vec![condition];
        while let Some(node) = stack.pop() {
            let node = unwrap_parenthesized_expression(node);
            if self.role(node, Role::Left).is_none() || self.role(node, Role::Right).is_none() {
                continue;
            }
            let Some(operator) = self.operator(node) else {
                continue;
            };
            if operator == "&&" {
                stack.extend([
                    self.role(node, Role::Left).expect("binary left"),
                    self.role(node, Role::Right).expect("binary right"),
                ]);
                continue;
            }
            let operands = match operator {
                "<" | "<=" => Some((Role::Left, Role::Right)),
                ">" | ">=" => Some((Role::Right, Role::Left)),
                _ => None,
            };
            if let Some((value_role, bound_role)) = operands
                && let Some(value) = self
                    .role(node, value_role)
                    .map(unwrap_parenthesized_expression)
                && self.is(value, NormalizedKind::Identifier)
                && value.utf8_text(source.as_bytes()).ok() == Some(variable.as_str())
                && let Some(bound) = self
                    .role(node, bound_role)
                    .map(unwrap_parenthesized_expression)
                && self.is(bound, NormalizedKind::Literal)
                && let Ok(bound) = bound
                    .utf8_text(source.as_bytes())
                    .unwrap_or("")
                    .parse::<i64>()
                && (0..=1).contains(&bound)
            {
                return true;
            }
        }
        false
    }

    fn alloca_in_loop(&self, call: Node<'_>, source: &str) -> bool {
        if !self.syntax.is_alloca(call, source) {
            return false;
        }
        let mut current = call.parent();
        while let Some(parent) = current {
            if self.is(parent, NormalizedKind::Loop) {
                if self
                    .syntax
                    .loop_initializers(parent)
                    .iter()
                    .any(|initializer| {
                        initializer.start_byte() <= call.start_byte()
                            && call.end_byte() <= initializer.end_byte()
                    })
                {
                    return false;
                }
                return !self.syntax.is_counted_loop(parent)
                    || !self.tightly_bounded(parent, source);
            }
            if self.callable(parent) {
                break;
            }
            current = parent.parent();
        }
        false
    }

    fn label<'tree>(&self, node: Node<'tree>, source: &'tree str) -> Option<&'tree str> {
        self.role(node, Role::Label)?
            .utf8_text(source.as_bytes())
            .ok()
    }

    fn labels_and_gotos<'tree>(
        &self,
        function: Node<'tree>,
        source: &'tree str,
    ) -> JumpSites<'tree> {
        let mut labels = Vec::new();
        let mut gotos = Vec::new();
        let mut stack = vec![function];
        while let Some(node) = stack.pop() {
            if node != function && self.callable(node) {
                continue;
            }
            if let Some(name) = self.label(node, source) {
                if self.is(node, NormalizedKind::Label) {
                    labels.push((name, node.start_position().row));
                }
                if self.is(node, NormalizedKind::Goto) {
                    gotos.push((name, node.start_position().row));
                }
            }
            stack.extend(named_children_iter(node).filter(|child| !child.is_extra()));
        }
        JumpSites { labels, gotos }
    }

    fn goto_counts(&self, function: Node<'_>, source: &str) -> (usize, usize) {
        let JumpSites { labels, gotos } = self.labels_and_gotos(function, source);
        let labels: HashMap<_, _> = labels.into_iter().collect();
        gotos
            .into_iter()
            .fold((0, 0), |(forward, backward), (name, line)| {
                match labels.get(name).copied() {
                    Some(target) if line < target => (forward + 1, backward),
                    Some(target) if target < line => (forward, backward + 1),
                    _ => (forward, backward),
                }
            })
    }

    fn empty_conditional(
        &self,
        block: Node<'_>,
        regions: &ConditionalRegions,
    ) -> Option<BodyStateAnswer> {
        // A grammar wrapper may sit between an arm and its owning if. Stop
        // at the first normalized owner so an inner block cannot borrow an
        // enclosing if's ownership.
        let owner = std::iter::successors(block.parent(), |node| node.parent())
            .find(|node| self.kind(*node).is_some())?;
        (self.is(owner, NormalizedKind::If)
            && [Role::Consequence, Role::Alternative]
                .into_iter()
                .any(|role| self.syntax.roles(owner, role).contains(&block)))
        .then(|| body_state(block, regions))
    }

    pub fn classify(
        &self,
        node: Node<'_>,
        source: &str,
        regions: &ConditionalRegions,
    ) -> Option<StatementFactKind> {
        match self.kind(node)? {
            NormalizedKind::Call if self.alloca_in_loop(node, source) => {
                Some(StatementFactKind::AllocaInLoop)
            }
            NormalizedKind::Block => {
                if self.complex_statement_count(node) > 3 {
                    Some(StatementFactKind::ComplexBlock)
                } else if self.empty_conditional(node, regions)
                    == Some(BodyStateAnswer::Decided(BodyState::Empty))
                {
                    Some(StatementFactKind::EmptyBlock)
                } else {
                    None
                }
            }
            NormalizedKind::If
                if self
                    .role(node, Role::Test)
                    .is_some_and(|test| self.logical_operator_count(test) > 5) =>
            {
                Some(StatementFactKind::ComplexCondition)
            }
            NormalizedKind::Switch => {
                let cases = self.switch_cases(node);
                if self.long_case(node, &cases) {
                    Some(StatementFactKind::LongSwitch)
                } else if self.missing_case(node, &cases, source) {
                    Some(StatementFactKind::MissingCaseInSwitch)
                } else {
                    None
                }
            }
            NormalizedKind::Function | NormalizedKind::Method | NormalizedKind::Constructor => {
                let (forward, backward) = self.goto_counts(node, source);
                (forward > 0 && backward > 0 && forward != 1 && backward != 1)
                    .then_some(StatementFactKind::UseOfGoto)
            }
            _ => None,
        }
    }

    pub fn capture(
        &self,
        node: Node<'_>,
        source: &str,
        regions: &ConditionalRegions,
        rows: &mut StatementFactRows,
    ) {
        let range = node_range(node);
        // Each kind uses its own owner, even when no positive row would have
        // passed its threshold. An unproven negative is not a complete answer.
        let mut undecided = Vec::new();
        let mut check_owner = |owner: Node<'_>, kind| {
            if regions.has_uncertain_text(owner.byte_range()) {
                undecided.push(StatementFact {
                    range: node_range(owner),
                    kind,
                });
            }
        };
        match self.kind(node) {
            Some(NormalizedKind::Block) => {
                check_owner(node, StatementFactKind::ComplexBlock);
                if let Some(answer) = self.empty_conditional(node, regions) {
                    check_owner(node, StatementFactKind::EmptyBlock);
                    if answer == BodyStateAnswer::Undecided
                        && !undecided
                            .iter()
                            .any(|fact| fact.kind == StatementFactKind::EmptyBlock)
                    {
                        undecided.push(StatementFact {
                            range,
                            kind: StatementFactKind::EmptyBlock,
                        });
                    }
                }
            }
            Some(NormalizedKind::If) => {
                if let Some(condition) = self.role(node, Role::Test) {
                    check_owner(condition, StatementFactKind::ComplexCondition);
                }
            }
            Some(NormalizedKind::Switch) => {
                check_owner(node, StatementFactKind::LongSwitch);
                check_owner(node, StatementFactKind::MissingCaseInSwitch);
            }
            Some(
                NormalizedKind::Function | NormalizedKind::Method | NormalizedKind::Constructor,
            ) => check_owner(node, StatementFactKind::UseOfGoto),
            Some(NormalizedKind::Call) => check_owner(node, StatementFactKind::AllocaInLoop),
            _ => {}
        }
        let decided = |kind| !undecided.iter().any(|fact| fact.kind == kind);
        if let Some(kind) = self.classify(node, source, regions)
            && decided(kind)
        {
            rows.statements.push(StatementFact { range, kind });
        }
        if self.is(node, NormalizedKind::Switch) && decided(StatementFactKind::LongSwitch) {
            let cases = self.switch_cases(node);
            let long_case = self.long_case(node, &cases);
            let missing_case = self.missing_case(node, &cases, source);
            for (kind, present) in [
                (StatementFactKind::LongSwitch, long_case),
                (StatementFactKind::MissingCaseInSwitch, missing_case),
            ] {
                if present
                    && !rows
                        .statements
                        .iter()
                        .any(|fact| fact.range == range && fact.kind == kind)
                {
                    rows.statements.push(StatementFact { range, kind });
                }
            }
            for case in &cases {
                let value = self
                    .role(*case, Role::Test)
                    .and_then(|node| self.syntax.name(node))
                    .and_then(|name| name.utf8_text(source.as_bytes()).ok())
                    .map(str::to_owned);
                rows.switch_cases.push(SwitchCaseFact {
                    range: node_range(*case),
                    value,
                });
            }
            rows.switches.push(SwitchFact {
                range,
                case_count: cases.len(),
                default_present: self.default_present(&cases),
                long_case,
                missing_enum_case: missing_case,
            });
        }
        if self.is(node, NormalizedKind::If)
            && decided(StatementFactKind::ComplexCondition)
            && let Some(condition) = self.role(node, Role::Test)
        {
            rows.conditions.push(ConditionFact {
                range: node_range(condition),
                logical_operator_count: self.logical_operator_count(condition),
            });
        }
        if self.is(node, NormalizedKind::Loop) {
            rows.loops.push(LoopFact {
                range,
                variable: self.syntax.loop_variable(node, source),
                body_statement_count: self
                    .role(node, Role::Body)
                    .map(|body| self.child_count(body))
                    .unwrap_or_default(),
                tightly_bounded: self.syntax.is_counted_loop(node)
                    && self.tightly_bounded(node, source),
            });
        }
        if self.is(node, NormalizedKind::Label)
            && let Some(name) = self.label(node, source)
        {
            rows.labels.push(LabelFact {
                range,
                name: name.to_owned(),
            });
        }
        if self.is(node, NormalizedKind::Goto)
            && let Some(target) = self.label(node, source)
        {
            let mut owner = node;
            while let Some(parent) = owner.parent() {
                owner = parent;
                if self.callable(parent) {
                    break;
                }
            }
            // The original lookup visits labels in reverse source order.
            let labels = self.labels_and_gotos(owner, source).labels;
            let forward = labels
                .iter()
                .find(|(name, _)| *name == target)
                .is_some_and(|(_, line)| node.start_position().row < *line);
            rows.gotos.push(GotoFact {
                range,
                target: target.to_owned(),
                forward,
            });
        }
        if let Some((enumeration, enumerators)) = self.syntax.enumeration(node, source) {
            rows.enums.push(enumeration);
            rows.enumerators.extend(enumerators);
        }
        rows.undecided.extend(
            undecided
                .into_iter()
                .filter(|fact| self.syntax.supports_kind(fact.kind)),
        );
    }
}

/// Parse-tree traversal retains only the result of this source-local query.
pub fn capture_statement_facts(
    spec: &dyn StructuralSpec,
    root: Node<'_>,
    source: &str,
) -> StatementFactRows {
    let mut rows = StatementFactRows::default();
    let Some(producer) = StatementFacts::new(spec) else {
        return rows;
    };
    let regions = spec.conditional_regions(root, source);
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        producer.capture(node, source, &regions, &mut rows);
        let children: Vec<_> = named_children_iter(node).collect();
        stack.extend(children.into_iter().rev());
    }
    rows
}
