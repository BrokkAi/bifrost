//! Query-time Python C3 hierarchy and inherited-member relations.

use super::python_rule_facts::{direct_identifier, named_children, node_text};
use super::*;
use crate::analyzer::semantic::type_flow::ClassIdentity;
use crate::analyzer::usages::callable_signature::callable_signature_reports;
use crate::analyzer::usages::python_class_hierarchy::PythonAncestryBasis;
use crate::analyzer::usages::python_class_hierarchy::{
    PythonBaseFact, PythonBaseOrigin, PythonBaseResolution, PythonClassHierarchyAnswer,
    PythonClassHierarchyProvider, PythonHierarchyOutcome, PythonHierarchyReason, PythonMroMember,
    PythonMroMembersAnswer, PythonOverrideAnswer, PythonOverrideOutcome,
};

pub(super) fn hierarchy_incompleteness(reason: Option<PythonHierarchyReason>) -> Incompleteness {
    match reason {
        Some(PythonHierarchyReason::Cancelled) => {
            Incompleteness::Operational(DerivationExecutionCause::Cancelled)
        }
        Some(PythonHierarchyReason::VisitLimit) => {
            Incompleteness::Operational(DerivationExecutionCause::Budget)
        }
        Some(
            PythonHierarchyReason::NotClass
            | PythonHierarchyReason::UnresolvedBase
            | PythonHierarchyReason::NonClassBase
            | PythonHierarchyReason::ExternalBase
            | PythonHierarchyReason::MissingRuntimeBases
            | PythonHierarchyReason::ConflictingRuntimeBases
            | PythonHierarchyReason::AmbiguousRuntimeBase
            | PythonHierarchyReason::UnsupportedBaseExpression
            | PythonHierarchyReason::UnknownMemberSurface
            | PythonHierarchyReason::DuplicateBase
            | PythonHierarchyReason::CyclicBases
            | PythonHierarchyReason::InconsistentLinearization
            | PythonHierarchyReason::NotEffectiveMember,
        )
        | None => Incompleteness::Content,
    }
}

const PYTHON_HIERARCHY_FACT_ID_DOMAIN: &[u8] = b"bifrost.code_query.python_hierarchy_fact.v2";
const MAX_PYTHON_BASE_BRANCH_MEMBER_VISITS: usize = 16_384;
pub(super) const PYTHON_HIERARCHY_FACT_KIND_LABELS: &[&str] = &[
    "hierarchy",
    "base",
    "mro",
    "member",
    "override",
    "call_lifecycle",
    "call_context",
    "override_signature",
    "inference_failure",
];
pub(super) const PYTHON_HIERARCHY_OUTCOME_LABELS: &[&str] = &[
    "complete",
    "inconsistent",
    "incomplete",
    "unsupported",
    "resolved",
    "unresolved",
    "non_class",
    "external",
    "selected",
    "overrides",
    "no_override",
    "missing_call",
    "multiple_calls",
    "called",
    "no_issue",
    "super_mismatch",
    "explicit_delete_call",
    "approved_cleanup",
    "init_calls_subclass",
];
pub(super) const PYTHON_HIERARCHY_REASON_LABELS: &[&str] = &[
    "not_class",
    "unresolved_base",
    "non_class_base",
    "external_base",
    "missing_runtime_bases",
    "conflicting_runtime_bases",
    "ambiguous_runtime_base",
    "unsupported_base_expression",
    "unknown_member_surface",
    "base_branch_members_unavailable",
    "duplicate_base",
    "cyclic_bases",
    "inconsistent_linearization",
    "not_effective_member",
    "visit_limit",
    "cancelled",
    "unsupported_language",
    "unresolved_dispatch",
    "dynamic_dispatch",
    "conditional_call",
    "receiver_binding_unknown",
    "target_receiver_read_unavailable",
    "incomplete_hierarchy",
    "unsupported_call_shape",
    "unresolved_super_binding",
    "deferred_body",
];
pub(super) const PYTHON_BASE_RESOLUTION_LABELS: &[&str] =
    &["resolved", "unresolved", "non_class", "external"];
pub(super) const PYTHON_HIERARCHY_COVERAGE_LABELS: &[&str] = &["complete", "open"];

#[derive(Debug, Clone)]
pub(super) struct PythonHierarchyFactValue {
    pub(super) incompleteness: Incompleteness,
    pub(super) root: DeclarationValue,
    pub(super) root_id: String,
    pub(super) ancestry_basis: PythonAncestryBasis,
    pub(super) endpoint_ids: [Option<String>; 4],
    pub(super) site_range: Option<Range>,
    pub(super) fact_kind: &'static str,
    pub(super) outcome: &'static str,
    pub(super) reason: Option<&'static str>,
    pub(super) coverage: &'static str,
    pub(super) ordinal: Option<usize>,
    pub(super) base_spelling: Option<String>,
    pub(super) base_resolution: Option<&'static str>,
    pub(super) declaration: Option<ClassIdentity>,
    pub(super) owner: Option<ClassIdentity>,
    pub(super) target: Option<ClassIdentity>,
    pub(super) target_owner: Option<ClassIdentity>,
    pub(super) member_name: Option<String>,
    pub(super) mro_rank: Option<usize>,
    pub(super) target_non_trivial: Option<bool>,
    pub(super) target_reads_self: Option<bool>,
    pub(super) base_branch_definition_count: Option<usize>,
    pub(super) has_strict_ordering: Option<bool>,
    pub(super) has_non_strict_ordering: Option<bool>,
    pub(super) total_ordering_decorator: Option<bool>,
    pub(super) inherited_ne_present: Option<bool>,
    pub(super) inherited_ne_delegates: Option<bool>,
    pub(super) override_signatures: Option<PythonOverrideSignaturePair>,
}

#[derive(Debug, Clone, Copy, Default)]
struct PythonClassMemberProtocolFacts {
    has_strict_ordering: Option<bool>,
    has_non_strict_ordering: Option<bool>,
    total_ordering_decorator: Option<bool>,
    inherited_ne_present: Option<bool>,
    inherited_ne_delegates: Option<bool>,
}

#[derive(Debug, Clone)]
pub(super) struct PythonOverrideSignaturePair {
    pub(super) source: PythonCallableArityFact,
    pub(super) target: Option<PythonCallableArityFact>,
}

#[derive(Debug, Clone)]
pub(super) struct PythonCallableArityFact {
    pub(super) id: String,
    pub(super) ordinal: usize,
    pub(super) coverage: &'static str,
    pub(super) required_arity: Option<usize>,
    pub(super) total_arity: Option<usize>,
    pub(super) repeated: Option<bool>,
}

impl PythonHierarchyFactValue {
    pub(super) fn finalize_endpoints(&mut self, analyzer: &dyn IAnalyzer) {
        self.endpoint_ids = [
            &self.declaration,
            &self.owner,
            &self.target,
            &self.target_owner,
        ]
        .map(|endpoint| {
            endpoint
                .as_ref()
                .map(|endpoint| render::python_hierarchy_endpoint_id(analyzer, endpoint))
        });
    }

    pub(super) fn file(&self) -> &ProjectFile {
        self.root.unit.source()
    }

    pub(super) fn id(&self) -> String {
        let mut digest = LengthDelimitedDigest::new(PYTHON_HIERARCHY_FACT_ID_DOMAIN);
        digest.push(self.root_id.as_bytes());
        digest.push(self.fact_kind.as_bytes());
        digest.push(self.outcome.as_bytes());
        if let Some(ordinal) = self.ordinal {
            digest.push(&(ordinal as u64).to_be_bytes());
        }
        if let Some(spelling) = &self.base_spelling {
            digest.push(spelling.as_bytes());
        }
        if let Some(name) = &self.member_name {
            digest.push(name.as_bytes());
        }
        for (slot, identity) in self.endpoint_ids.iter().enumerate() {
            digest.push(&(slot as u64).to_be_bytes());
            digest.push(identity.as_deref().unwrap_or("").as_bytes());
        }
        if let Some(range) = self.site_range {
            digest.push(&range.start_byte.to_be_bytes());
            digest.push(&range.end_byte.to_be_bytes());
        }
        if let Some(signatures) = &self.override_signatures {
            digest.push(signatures.source.id.as_bytes());
            if let Some(target) = &signatures.target {
                digest.push(target.id.as_bytes());
            }
        }
        digest.finish().to_string()
    }
}

/// A derived decision and the actual source-root hierarchy premises used to
/// reach it. These are existing hierarchy facts, not a second evidence carrier.
#[derive(Debug, Clone)]
pub(super) struct HierarchyDecision<T> {
    pub(super) value: T,
    pub(super) premises: Vec<PythonHierarchyFactValue>,
}

impl<T> HierarchyDecision<T> {
    pub(super) fn plain(value: T) -> Self {
        Self {
            value,
            premises: Vec::new(),
        }
    }
}

/// Build a premise from an answer already obtained by the deriving operation.
/// A missing source declaration range cannot be replaced by an invented anchor.
pub(super) fn hierarchy_premise(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    answer: &PythonClassHierarchyAnswer,
) -> Option<PythonHierarchyFactValue> {
    let range = analyzer
        .ranges_of(unit)
        .into_iter()
        .min_by_key(primary_range_key)?;
    let declaration = DeclarationValue::new(unit.clone(), range);
    let root_id = render::canonical_member_digest(analyzer, unit);
    let expansion = hierarchy_outcome_fact(&declaration, &root_id, answer);
    let PipelineValue::PythonHierarchyFact(mut value) = expansion.value else {
        unreachable!("hierarchy outcome produces a hierarchy fact")
    };
    value.ancestry_basis = answer.ancestry_basis.clone();
    value.finalize_endpoints(analyzer);
    Some(*value)
}

/// Preserve member-inventory coverage independently of its nested topology.
pub(super) fn member_premise(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    answer: &PythonMroMembersAnswer,
) -> Option<PythonHierarchyFactValue> {
    let mut value = hierarchy_premise(analyzer, unit, &answer.hierarchy)?;
    value.fact_kind = "member";
    value.outcome = answer.outcome.label();
    value.reason = answer.reason.map(PythonHierarchyReason::label);
    value.incompleteness = hierarchy_incompleteness(answer.reason);
    value.coverage = if answer.outcome == PythonHierarchyOutcome::Complete {
        "complete"
    } else {
        "open"
    };
    Some(value)
}

pub(super) fn override_premise(
    analyzer: &dyn IAnalyzer,
    method: &CodeUnit,
    answer: &PythonOverrideAnswer,
) -> Option<PythonHierarchyFactValue> {
    let range = analyzer
        .ranges_of(method)
        .into_iter()
        .min_by_key(primary_range_key)?;
    let declaration = DeclarationValue::new(method.clone(), range);
    let root_id = render::canonical_member_digest(analyzer, method);
    let expansion = override_fact(&declaration, &root_id, answer);
    let PipelineValue::PythonHierarchyFact(mut value) = expansion.value else {
        unreachable!("override answer produces an override fact")
    };
    value.ancestry_basis = answer.ancestry_basis.clone();
    value.finalize_endpoints(analyzer);
    Some(*value)
}

pub(super) fn attach_hierarchy_premises(
    expansion: &mut PipelineExpansion,
    premises: &[PythonHierarchyFactValue],
) {
    let incompleteness = premises
        .iter()
        .fold(Incompleteness::Content, |cause, premise| {
            cause.combine(premise.incompleteness)
        });
    match &mut expansion.value {
        PipelineValue::PythonRuleFact(value) => {
            value.incompleteness = value.incompleteness.combine(incompleteness)
        }
        PipelineValue::PythonHierarchyFact(value) => {
            value.incompleteness = value.incompleteness.combine(incompleteness)
        }
        _ => {}
    }
    // Preserve the terminal trace entry and its identity as the last result.
    expansion.trace.splice(
        0..0,
        premises.iter().cloned().map(|value| {
            (
                PipelineTraceValue::PythonHierarchyFact(Box::new(value)),
                None,
            )
        }),
    );
}

pub(super) fn python_hierarchy_expansions_for_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    step: QueryStep,
    cancellation: Option<&CancellationToken>,
) -> Vec<PipelineExpansion> {
    let root_id = render::canonical_member_digest(analyzer, &declaration.unit);
    let Some(provider) = analyzer.python_class_hierarchy_provider_for(&declaration.unit) else {
        return match step {
            QueryStep::ClassHierarchy | QueryStep::MroMembers | QueryStep::ClassMro => {
                vec![fact_expansion(
                    Incompleteness::Content,
                    declaration,
                    &root_id,
                    "hierarchy",
                    "unsupported",
                    Some("unsupported_language"),
                    "open",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )]
            }
            QueryStep::ClassBases => vec![fact_expansion(
                Incompleteness::Content,
                declaration,
                &root_id,
                "base",
                "unsupported",
                Some("unsupported_language"),
                "open",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )],
            QueryStep::PythonOverrides => vec![fact_expansion(
                Incompleteness::Content,
                declaration,
                &root_id,
                "override",
                "unsupported",
                Some("unsupported_language"),
                "open",
                None,
                None,
                None,
                Some(ClassIdentity::Workspace(declaration.unit.clone())),
                None,
                None,
                None,
                Some(declaration.unit.terminal_name().to_owned()),
                None,
            )],
            _ => unreachable!("only Python hierarchy steps call this helper"),
        };
    };

    let mut basis = PythonAncestryBasis::default();
    let mut expansions = (|| match step {
        QueryStep::ClassHierarchy => {
            let answer = provider.class_hierarchy(&declaration.unit, cancellation);
            basis = answer.ancestry_basis.clone();
            let mut facts = vec![hierarchy_outcome_fact(declaration, &root_id, &answer)];
            facts.extend(
                answer
                    .bases
                    .iter()
                    .filter_map(|base| inference_failure_fact(declaration, &root_id, base)),
            );
            facts
        }
        QueryStep::ClassBases => {
            let answer = provider.class_hierarchy(&declaration.unit, cancellation);
            basis = answer.ancestry_basis.clone();
            if answer.bases.is_empty() {
                return if answer.outcome == PythonHierarchyOutcome::Complete {
                    Vec::new()
                } else {
                    vec![hierarchy_outcome_fact(declaration, &root_id, &answer)]
                };
            }
            answer
                .bases
                .iter()
                .map(|base| base_fact(declaration, &root_id, &answer, base))
                .collect()
        }
        QueryStep::ClassMro => {
            let answer = provider.class_hierarchy(&declaration.unit, cancellation);
            basis = answer.ancestry_basis.clone();
            if answer.outcome != PythonHierarchyOutcome::Complete {
                return vec![hierarchy_outcome_fact(declaration, &root_id, &answer)];
            }
            answer
                .mro
                .iter()
                .enumerate()
                .map(|(rank, class)| {
                    fact_expansion(
                        Incompleteness::Content,
                        declaration,
                        &root_id,
                        "mro",
                        "complete",
                        None,
                        "complete",
                        Some(rank),
                        None,
                        None,
                        Some(class.clone()),
                        None,
                        None,
                        None,
                        None,
                        Some(rank),
                    )
                })
                .collect()
        }
        QueryStep::MroMembers => {
            let answer = provider.mro_members(&declaration.unit, cancellation);
            basis = answer.hierarchy.ancestry_basis.clone();
            if answer.hierarchy.outcome != PythonHierarchyOutcome::Complete {
                return vec![hierarchy_outcome_fact(
                    declaration,
                    &root_id,
                    &answer.hierarchy,
                )];
            }
            let mut rows = Vec::new();
            if answer.outcome != PythonHierarchyOutcome::Complete {
                let mut open = hierarchy_outcome_fact(declaration, &root_id, &answer.hierarchy);
                if let PipelineValue::PythonHierarchyFact(value) = &mut open.value {
                    value.fact_kind = "member";
                    value.outcome = answer.outcome.label();
                    value.reason = answer.reason.map(PythonHierarchyReason::label);
                    value.incompleteness = hierarchy_incompleteness(answer.reason);
                    value.coverage = "open";
                }
                rows.push(open);
            }
            let base_branch_counts =
                mro_base_branch_definition_counts(provider, &answer, cancellation);
            let protocol_facts =
                python_class_member_protocol_facts(analyzer, declaration, &answer, cancellation);
            rows.extend(answer.members.iter().enumerate().map(|(ordinal, member)| {
                member_fact(
                    declaration,
                    &root_id,
                    ordinal,
                    member,
                    base_branch_counts
                        .as_ref()
                        .ok()
                        .map(|counts| *counts.get(&member.name).unwrap_or(&0)),
                    base_branch_counts
                        .as_ref()
                        .err()
                        .copied()
                        .unwrap_or(Incompleteness::Content),
                    protocol_facts,
                )
            }));
            rows
        }
        QueryStep::PythonOverrides => {
            let answer = provider.method_override(&declaration.unit, cancellation);
            basis = answer.ancestry_basis.clone();
            vec![override_fact(declaration, &root_id, &answer)]
        }
        _ => unreachable!("only Python hierarchy steps call this helper"),
    })();
    for expansion in &mut expansions {
        if let PipelineValue::PythonHierarchyFact(value) = &mut expansion.value {
            value.ancestry_basis = basis.clone();
        }
    }
    expansions
}

fn python_class_member_protocol_facts(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    answer: &PythonMroMembersAnswer,
    cancellation: Option<&CancellationToken>,
) -> PythonClassMemberProtocolFacts {
    let has_strict_ordering = answer.members.iter().any(|member| {
        member.owner.fq_name_str() != "builtins.object"
            && member.member.is_function()
            && matches!(member.name.as_str(), "__lt__" | "__gt__")
    });
    let has_non_strict_ordering = answer.members.iter().any(|member| {
        member.owner.fq_name_str() != "builtins.object"
            && member.member.is_function()
            && matches!(member.name.as_str(), "__le__" | "__ge__")
    });
    let (inherited_ne_present, inherited_ne_delegates) =
        inherited_inequality_facts(analyzer, answer, cancellation);
    PythonClassMemberProtocolFacts {
        has_strict_ordering: (has_strict_ordering
            || answer.outcome == PythonHierarchyOutcome::Complete)
            .then_some(has_strict_ordering),
        has_non_strict_ordering: (has_non_strict_ordering
            || answer.outcome == PythonHierarchyOutcome::Complete)
            .then_some(has_non_strict_ordering),
        total_ordering_decorator: python_total_ordering_decorator(analyzer, declaration),
        inherited_ne_present,
        inherited_ne_delegates,
    }
}

fn inherited_inequality_facts(
    analyzer: &dyn IAnalyzer,
    answer: &PythonMroMembersAnswer,
    cancellation: Option<&CancellationToken>,
) -> (Option<bool>, Option<bool>) {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return (None, None);
    }
    // The provider has already selected each name in C3 order and stopped at
    // the first unknown member surface. Later ancestors cannot mask a selected
    // source method, and members beyond that frontier supply no callable proof.
    for member in &answer.members {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (None, None);
        }
        if member.name != "__ne__" {
            continue;
        }
        if member.rank == 0 {
            return (Some(false), Some(false));
        }
        if !member.member.is_function() {
            return (None, None);
        }
        let delegates = python_method_delegates_to_eq(analyzer, &member.member);
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (None, None);
        }
        return (Some(true), delegates);
    }
    if answer.outcome == PythonHierarchyOutcome::Complete {
        (Some(false), Some(false))
    } else {
        (None, None)
    }
}

fn python_total_ordering_decorator(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
) -> Option<bool> {
    use brokk_bifrost_python::imports::{
        PythonImportDetails, python_import_details, python_import_syntaxes_from_node,
    };

    let file = declaration.unit.source();
    let source = analyzer.get_source(&CodeUnit::file_scope(file.clone()), false)?;
    let tree = super::python_rule_facts::parse_python(&source)
        .filter(|tree| !tree.root_node().has_error())?;
    let class =
        super::python_rule_facts::python_class_node_for_unit(analyzer, &declaration.unit, &tree)?;
    let mut imported_names = HashMap::<String, (String, String)>::default();
    let mut imported_modules = HashMap::<String, String>::default();
    let mut wildcard_import = false;
    for statement in named_children(tree.root_node()) {
        if statement.start_byte() >= class.start_byte() {
            break;
        }
        if !matches!(
            statement.kind(),
            "import_statement" | "import_from_statement"
        ) {
            continue;
        }
        for syntax in python_import_syntaxes_from_node(statement, &source) {
            let Some(details) = python_import_details(&syntax.info) else {
                continue;
            };
            match details {
                PythonImportDetails::Import { module, alias } => {
                    let local = alias.unwrap_or_else(|| module.clone());
                    imported_modules.insert(local, module);
                }
                PythonImportDetails::FromImport {
                    module,
                    wildcard: true,
                    ..
                } if module == "functools" => wildcard_import = true,
                PythonImportDetails::FromImport {
                    module,
                    name,
                    alias,
                    wildcard: false,
                } => {
                    imported_names.insert(alias.unwrap_or_else(|| name.clone()), (module, name));
                }
                _ => {}
            }
        }
    }

    let mut uncertain = false;
    for decorator in super::python_rule_facts::python_definition_decorators(class) {
        let expression = named_children(decorator).into_iter().next()?;
        let callee = if expression.kind() == "call" {
            expression.child_by_field_name("function")?
        } else {
            expression
        };
        let Some(path) = python_expression_path(callee, &source) else {
            continue;
        };
        if let [name] = path.as_slice() {
            match imported_names.get(name) {
                Some((module, imported))
                    if module == "functools" && imported == "total_ordering" =>
                {
                    return Some(true);
                }
                Some(_) => continue,
                None if wildcard_import => uncertain = true,
                None => uncertain = true,
            }
        }
        if let [module, name] = path.as_slice() {
            match imported_modules.get(module) {
                Some(imported) if imported == "functools" && name == "total_ordering" => {
                    return Some(true);
                }
                Some(_) => continue,
                None if name == "total_ordering" => uncertain = true,
                None => {}
            }
        }
        if path.len() > 2 && path.last().is_some_and(|name| name == "total_ordering") {
            uncertain = true;
        }
    }
    (!uncertain).then_some(false)
}

fn python_expression_path(mut node: tree_sitter::Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut path = Vec::new();
    loop {
        match node.kind() {
            "identifier" => {
                path.push(node_text(source, node)?.to_owned());
                path.reverse();
                return Some(path);
            }
            "attribute" => {
                path.push(node_text(source, node.child_by_field_name("attribute")?)?.to_owned());
                node = node.child_by_field_name("object")?;
            }
            _ => return None,
        }
    }
}

fn python_method_delegates_to_eq(analyzer: &dyn IAnalyzer, method: &CodeUnit) -> Option<bool> {
    let range = super::python_rule_facts::python_range_for_unit(analyzer, method)?;
    let source = analyzer.get_source(&CodeUnit::file_scope(method.source().clone()), false)?;
    let tree = super::python_rule_facts::parse_python(&source)
        .filter(|tree| !tree.root_node().has_error())?;
    let definition = super::python_rule_facts::python_definition_node(&tree, method, &range)?;
    let parameters = definition.child_by_field_name("parameters")?;
    let parameter_names = named_children(parameters)
        .into_iter()
        .filter_map(|parameter| super::python_rule_facts::parameter_name(parameter, &source))
        .take(2)
        .collect::<Vec<_>>();
    let [receiver, other] = parameter_names.as_slice() else {
        return Some(false);
    };
    let body = definition.child_by_field_name("body")?;
    let mut stack = vec![body];
    let mut uncertain = false;
    while let Some(node) = stack.pop() {
        if node.id() != body.id()
            && matches!(
                node.kind(),
                "function_definition" | "class_definition" | "lambda"
            )
        {
            continue;
        }
        if node.kind() == "return_statement" {
            for expression in named_children(node) {
                match python_negated_equality_expression(expression, receiver, other, &source) {
                    Some(true) => return Some(true),
                    Some(false) => {}
                    None => uncertain = true,
                }
            }
        }
        stack.extend(named_children(node));
    }
    (!uncertain).then_some(false)
}

fn python_negated_equality_expression(
    expression: tree_sitter::Node<'_>,
    receiver: &str,
    other: &str,
    source: &str,
) -> Option<bool> {
    if expression.kind() != "not_operator" {
        return Some(false);
    }
    let operand = expression
        .child_by_field_name("argument")
        .or_else(|| named_children(expression).into_iter().next())?;
    let operand = unwrap_parenthesized(operand);
    if operand.kind() == "call"
        && let Some(function) = operand.child_by_field_name("function")
        && function.kind() == "attribute"
        && function
            .child_by_field_name("object")
            .is_some_and(|object| direct_identifier(object, source) == Some(receiver))
        && function
            .child_by_field_name("attribute")
            .and_then(|attribute| node_text(source, attribute))
            == Some("__eq__")
        && let Some(arguments) = operand.child_by_field_name("arguments")
    {
        let arguments = named_children(arguments);
        return Some(
            function
                .child_by_field_name("object")
                .is_some_and(|object| direct_identifier(object, source) == Some(receiver))
                && arguments.len() == 1
                && direct_identifier(arguments[0], source) == Some(other),
        );
    }
    if operand.kind() == "call"
        && operand
            .child_by_field_name("function")
            .and_then(|function| function.child_by_field_name("attribute"))
            .and_then(|attribute| node_text(source, attribute))
            == Some("__eq__")
    {
        return None;
    }
    if operand.kind() == "comparison_operator" {
        let shape = brokk_bifrost_python::structural::python_comparison_shape(operand);
        if shape.operator_count != 1 {
            return Some(false);
        }
        let operator = shape
            .operator
            .and_then(|operator| node_text(source, operator))?;
        if operator != "==" {
            return Some(false);
        }
        let direct = shape
            .left
            .is_some_and(|left| direct_identifier(left, source) == Some(receiver))
            && shape
                .right
                .is_some_and(|right| direct_identifier(right, source) == Some(other));
        return direct.then_some(true);
    }
    Some(false)
}

fn unwrap_parenthesized(mut node: tree_sitter::Node<'_>) -> tree_sitter::Node<'_> {
    while node.kind() == "parenthesized_expression" {
        let children = named_children(node);
        let [inner] = children.as_slice() else {
            break;
        };
        node = *inner;
    }
    node
}

pub(super) fn python_override_signature_expansions_for_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    cancellation: Option<&CancellationToken>,
) -> Vec<PipelineExpansion> {
    let root_id = render::canonical_member_digest(analyzer, &declaration.unit);
    let Some(provider) = analyzer.python_class_hierarchy_provider_for(&declaration.unit) else {
        let answer = PythonOverrideAnswer::stopped(
            PythonOverrideOutcome::Unsupported,
            None,
            None,
            PythonAncestryBasis::default(),
        );
        return vec![override_signature_fact_expansion(
            declaration,
            &root_id,
            &answer,
            None,
        )];
    };
    let answer = provider.method_override(&declaration.unit, cancellation);
    python_override_signature_expansions_for_answer(analyzer, declaration, &root_id, &answer)
}

fn python_override_signature_expansions_for_answer(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    root_id: &str,
    answer: &PythonOverrideAnswer,
) -> Vec<PipelineExpansion> {
    if answer.outcome != PythonOverrideOutcome::Overrides {
        return vec![override_signature_fact_expansion(
            declaration,
            root_id,
            answer,
            None,
        )];
    }

    let target = answer
        .target
        .as_ref()
        .expect("an override outcome carries its selected base method");
    let source_signatures = callable_arity_facts(analyzer, declaration);
    let target_range = analyzer
        .ranges_of(target)
        .into_iter()
        .min_by_key(super::primary_range_key);
    let Some(target_range) = target_range else {
        return source_signatures
            .into_iter()
            .map(|source| {
                override_signature_fact_expansion(
                    declaration,
                    root_id,
                    answer,
                    Some(PythonOverrideSignaturePair {
                        source,
                        target: None,
                    }),
                )
            })
            .collect();
    };
    let target_declaration = DeclarationValue::new(target.clone(), target_range);
    let target_signatures = callable_arity_facts(analyzer, &target_declaration);

    source_signatures
        .into_iter()
        .flat_map(|source| {
            target_signatures.iter().cloned().map(move |target| {
                override_signature_fact_expansion(
                    declaration,
                    root_id,
                    answer,
                    Some(PythonOverrideSignaturePair {
                        source: source.clone(),
                        target: Some(target),
                    }),
                )
            })
        })
        .collect()
}

fn callable_arity_facts(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
) -> Vec<PythonCallableArityFact> {
    let entries = analyzer.signature_metadata(&declaration.unit);
    callable_signature_reports(&declaration.site_id(), &declaration.unit, &entries)
        .into_iter()
        .map(|report| {
            let signature = report.signature;
            let (required_arity, total_arity, repeated) = signature
                .arity
                .map(|arity| {
                    (
                        Some(arity.required()),
                        Some(arity.total()),
                        Some(arity.is_repeated()),
                    )
                })
                .unwrap_or((None, None, None));
            PythonCallableArityFact {
                id: signature.id,
                ordinal: signature.ordinal,
                coverage: signature.coverage.label(),
                required_arity,
                total_arity,
                repeated,
            }
        })
        .collect()
}

fn override_signature_fact_expansion(
    declaration: &DeclarationValue,
    root_id: &str,
    answer: &PythonOverrideAnswer,
    override_signatures: Option<PythonOverrideSignaturePair>,
) -> PipelineExpansion {
    let coverage = match answer.outcome {
        PythonOverrideOutcome::NoOverride => "complete",
        PythonOverrideOutcome::Overrides
            if override_signatures.as_ref().is_some_and(|signatures| {
                signatures.source.coverage == "exact"
                    && signatures.source.required_arity.is_some()
                    && signatures.source.total_arity.is_some()
                    && signatures.source.repeated.is_some()
                    && signatures
                        .target
                        .as_ref()
                        .is_some_and(|target| target.coverage == "exact")
                    && signatures.target.as_ref().is_some_and(|target| {
                        target.required_arity.is_some()
                            && target.total_arity.is_some()
                            && target.repeated.is_some()
                    })
            }) =>
        {
            "complete"
        }
        PythonOverrideOutcome::Overrides
        | PythonOverrideOutcome::Incomplete
        | PythonOverrideOutcome::Unsupported => "open",
    };
    pipeline_expansion(PipelineValue::PythonHierarchyFact(Box::new(
        PythonHierarchyFactValue {
            incompleteness: hierarchy_incompleteness(answer.reason),
            root: declaration.clone(),
            root_id: root_id.to_owned(),
            ancestry_basis: answer.ancestry_basis.clone(),
            endpoint_ids: Default::default(),
            site_range: None,
            fact_kind: "override_signature",
            outcome: answer.outcome.label(),
            reason: answer.reason.map(PythonHierarchyReason::label),
            coverage,
            ordinal: None,
            base_spelling: None,
            base_resolution: None,
            declaration: Some(ClassIdentity::Workspace(declaration.unit.clone())),
            owner: answer.source_owner.clone().map(ClassIdentity::Workspace),
            target: answer.target.clone().map(ClassIdentity::Workspace),
            target_owner: answer.target_owner.clone().map(ClassIdentity::Workspace),
            member_name: Some(declaration.unit.terminal_name().to_owned()),
            mro_rank: answer.mro_rank,
            target_non_trivial: None,
            target_reads_self: None,
            base_branch_definition_count: None,
            has_strict_ordering: None,
            has_non_strict_ordering: None,
            total_ordering_decorator: None,
            inherited_ne_present: None,
            inherited_ne_delegates: None,
            override_signatures,
        },
    )))
}

fn hierarchy_outcome_fact(
    declaration: &DeclarationValue,
    root_id: &str,
    answer: &PythonClassHierarchyAnswer,
) -> PipelineExpansion {
    fact_expansion(
        hierarchy_incompleteness(answer.reason),
        declaration,
        root_id,
        "hierarchy",
        answer.outcome.label(),
        answer.reason.map(PythonHierarchyReason::label),
        answer.coverage(),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

fn base_fact(
    declaration: &DeclarationValue,
    root_id: &str,
    hierarchy: &PythonClassHierarchyAnswer,
    base: &PythonBaseFact,
) -> PipelineExpansion {
    let reason = match base.resolution {
        PythonBaseResolution::Resolved => None,
        PythonBaseResolution::Unresolved => Some(
            match base.origin {
                PythonBaseOrigin::Source => PythonHierarchyReason::UnresolvedBase,
                PythonBaseOrigin::ImplicitObject => PythonHierarchyReason::MissingRuntimeBases,
            }
            .label(),
        ),
        PythonBaseResolution::NonClass => Some(PythonHierarchyReason::NonClassBase.label()),
        PythonBaseResolution::External => Some(PythonHierarchyReason::ExternalBase.label()),
    };
    fact_expansion(
        hierarchy_incompleteness(hierarchy.reason),
        declaration,
        root_id,
        "base",
        base.resolution.label(),
        reason,
        hierarchy.coverage(),
        Some(base.ordinal),
        Some(base.spelling.clone()),
        Some(base.resolution.label()),
        None,
        None,
        base.target.clone(),
        None,
        None,
        None,
    )
}

fn inference_failure_fact(
    declaration: &DeclarationValue,
    root_id: &str,
    base: &PythonBaseFact,
) -> Option<PipelineExpansion> {
    if base.origin == PythonBaseOrigin::ImplicitObject {
        return None;
    }
    let reason = match base.resolution {
        PythonBaseResolution::Unresolved => PythonHierarchyReason::UnresolvedBase,
        PythonBaseResolution::NonClass => PythonHierarchyReason::NonClassBase,
        PythonBaseResolution::Resolved | PythonBaseResolution::External => return None,
    };
    Some(fact_expansion(
        Incompleteness::Content,
        declaration,
        root_id,
        "inference_failure",
        base.resolution.label(),
        Some(reason.label()),
        "complete",
        Some(base.ordinal),
        Some(base.spelling.clone()),
        Some(base.resolution.label()),
        None,
        None,
        base.target.clone(),
        None,
        None,
        None,
    ))
}

fn member_fact(
    declaration: &DeclarationValue,
    root_id: &str,
    ordinal: usize,
    member: &PythonMroMember,
    base_branch_definition_count: Option<usize>,
    incompleteness: Incompleteness,
    protocol_facts: PythonClassMemberProtocolFacts,
) -> PipelineExpansion {
    let mut expansion = fact_expansion(
        Incompleteness::Content,
        declaration,
        root_id,
        "member",
        "selected",
        None,
        "complete",
        Some(ordinal),
        None,
        None,
        Some(ClassIdentity::Workspace(member.member.clone())),
        Some(ClassIdentity::Workspace(member.owner.clone())),
        None,
        None,
        Some(member.name.clone()),
        Some(member.rank),
    );
    let PipelineValue::PythonHierarchyFact(value) = &mut expansion.value else {
        unreachable!("MRO member facts use the Python hierarchy value")
    };
    value.base_branch_definition_count = base_branch_definition_count;
    value.has_strict_ordering = protocol_facts.has_strict_ordering;
    value.has_non_strict_ordering = protocol_facts.has_non_strict_ordering;
    value.total_ordering_decorator = protocol_facts.total_ordering_decorator;
    value.inherited_ne_present = protocol_facts.inherited_ne_present;
    value.inherited_ne_delegates = protocol_facts.inherited_ne_delegates;
    if base_branch_definition_count.is_none() {
        value.coverage = "open";
        value.reason = Some("base_branch_members_unavailable");
        value.incompleteness = incompleteness;
    }
    expansion
}

fn mro_base_branch_definition_counts(
    provider: &dyn PythonClassHierarchyProvider,
    answer: &PythonMroMembersAnswer,
    cancellation: Option<&CancellationToken>,
) -> Result<HashMap<String, usize>, Incompleteness> {
    let mut declarations = HashMap::<String, Vec<CodeUnit>>::default();
    let mut visits = 0usize;
    for base in &answer.hierarchy.bases {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(Incompleteness::Operational(
                DerivationExecutionCause::Cancelled,
            ));
        }
        if base.origin == PythonBaseOrigin::ImplicitObject {
            // The language-supplied object root is not a source branch.
            continue;
        }
        if base.resolution != PythonBaseResolution::Resolved {
            return Err(Incompleteness::Content);
        }
        let Some(ClassIdentity::Workspace(unit)) = base.target.as_ref() else {
            return Err(Incompleteness::Content);
        };
        let branch = provider.mro_members(unit, cancellation);
        if branch.outcome != PythonHierarchyOutcome::Complete {
            return Err(branch.reason.map_or(
                Incompleteness::Operational(DerivationExecutionCause::Provider),
                |reason| hierarchy_incompleteness(Some(reason)),
            ));
        }
        visits = visits.saturating_add(branch.members.len());
        if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
            visits,
            MAX_PYTHON_BASE_BRANCH_MEMBER_VISITS,
        )
        .allows(0)
        {
            return Err(Incompleteness::Operational(
                DerivationExecutionCause::Budget,
            ));
        }
        for member in branch.members {
            let candidates = declarations.entry(member.name).or_default();
            if !candidates.contains(&member.member) {
                candidates.push(member.member);
            }
        }
    }
    Ok(declarations
        .into_iter()
        .map(|(name, declarations)| (name, declarations.len()))
        .collect())
}

fn override_fact(
    declaration: &DeclarationValue,
    root_id: &str,
    answer: &PythonOverrideAnswer,
) -> PipelineExpansion {
    fact_expansion(
        hierarchy_incompleteness(answer.reason),
        declaration,
        root_id,
        "override",
        answer.outcome.label(),
        answer.reason.map(PythonHierarchyReason::label),
        match answer.outcome {
            PythonOverrideOutcome::Overrides | PythonOverrideOutcome::NoOverride => "complete",
            PythonOverrideOutcome::Incomplete | PythonOverrideOutcome::Unsupported => "open",
        },
        None,
        None,
        None,
        Some(ClassIdentity::Workspace(declaration.unit.clone())),
        answer.source_owner.clone().map(ClassIdentity::Workspace),
        answer.target.clone().map(ClassIdentity::Workspace),
        answer.target_owner.clone().map(ClassIdentity::Workspace),
        Some(declaration.unit.terminal_name().to_owned()),
        answer.mro_rank,
    )
}

#[allow(clippy::too_many_arguments)]
fn fact_expansion(
    incompleteness: Incompleteness,
    declaration: &DeclarationValue,
    root_id: &str,
    fact_kind: &'static str,
    outcome: &'static str,
    reason: Option<&'static str>,
    coverage: &'static str,
    ordinal: Option<usize>,
    base_spelling: Option<String>,
    base_resolution: Option<&'static str>,
    member: Option<ClassIdentity>,
    owner: Option<ClassIdentity>,
    target: Option<ClassIdentity>,
    target_owner: Option<ClassIdentity>,
    member_name: Option<String>,
    mro_rank: Option<usize>,
) -> PipelineExpansion {
    pipeline_expansion(PipelineValue::PythonHierarchyFact(Box::new(
        PythonHierarchyFactValue {
            incompleteness,
            root: declaration.clone(),
            root_id: root_id.to_owned(),
            ancestry_basis: PythonAncestryBasis::default(),
            endpoint_ids: Default::default(),
            site_range: None,
            fact_kind,
            outcome,
            reason,
            coverage,
            ordinal,
            base_spelling,
            base_resolution,
            declaration: member,
            owner,
            target,
            target_owner,
            member_name,
            mro_rank,
            target_non_trivial: None,
            target_reads_self: None,
            base_branch_definition_count: None,
            has_strict_ordering: None,
            has_non_strict_ordering: None,
            total_ordering_decorator: None,
            inherited_ne_present: None,
            inherited_ne_delegates: None,
            override_signatures: None,
        },
    )))
}
