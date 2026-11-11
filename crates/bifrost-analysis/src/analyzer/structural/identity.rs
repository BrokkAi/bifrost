//! Structural identity of two parsed subtrees, with explicit open reasons.
use super::lexical_environment::{BindingOfOutcome, EnvironmentFileResult, binding_of};
use super::occurrences::Namespace;
use super::resolution::BindingKind;
use crate::analyzer::languages::language_support_for_hook;
use crate::analyzer::{CodeUnit, CodeUnitType};
use crate::analyzer::{Language, Range};
use brokk_bifrost_core::analyzer::tree_walk::has_child_of_kind as has_direct_token;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub(super) const MAX_COMPARISON_TREE_NODES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityOpenReason {
    SyntaxRecovery,
    MissingField,
    LexicalBindingUnavailable,
    NonLocalReference,
    ComparisonBudget,
    MemberResolutionUnavailable,
    AmbiguousMember,
    DeferredBody,
    UnprovenActivation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityVerdict {
    Identical,
    Distinct,
    Open(IdentityOpenReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverLookupPolicy {
    ProofRequired,
    ReceiverOnly,
    CSharpUsings,
    KotlinExtensions,
    ScalaImportsImplicits,
    RustUsesTraits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentObjectOwner {
    NamedSelfType,
    Other,
}

pub trait IdentityBudget {
    fn step(&mut self) -> Result<(), IdentityOpenReason>;
    fn visit(
        &mut self,
        node: Node<'_>,
        visited: &mut usize,
        pending: usize,
    ) -> Result<(), IdentityOpenReason>;
    fn charge_comparison(&mut self) -> Result<(), IdentityOpenReason>;
    fn exhausted(&self) -> bool;
}

/// The bounded work allowance for one on-demand structural comparison.
pub struct StandardIdentityBudget {
    remaining: usize,
}

impl StandardIdentityBudget {
    pub fn standard() -> Self {
        Self {
            remaining: 120 * 2 * MAX_COMPARISON_TREE_NODES,
        }
    }
}

impl IdentityBudget for StandardIdentityBudget {
    fn step(&mut self) -> Result<(), IdentityOpenReason> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(IdentityOpenReason::ComparisonBudget)?;
        Ok(())
    }

    fn visit(
        &mut self,
        node: Node<'_>,
        visited: &mut usize,
        pending: usize,
    ) -> Result<(), IdentityOpenReason> {
        self.step()?;
        *visited += 1;
        if *visited > MAX_COMPARISON_TREE_NODES
            || node.child_count() > MAX_COMPARISON_TREE_NODES
            || pending.saturating_add(node.child_count()) > MAX_COMPARISON_TREE_NODES
        {
            self.remaining = 0;
            return Err(IdentityOpenReason::ComparisonBudget);
        }
        Ok(())
    }

    fn charge_comparison(&mut self) -> Result<(), IdentityOpenReason> {
        self.step()
    }

    fn exhausted(&self) -> bool {
        self.remaining == 0
    }
}

pub trait IdentityProofs {
    fn target_at(&self, node: Node<'_>) -> Result<&CodeUnit, IdentityOpenReason>;
    fn same_storage_field(&self, left: Node<'_>, right: Node<'_>) -> bool;
    fn has_storage_field(&self, node: Node<'_>) -> bool;
    fn has_collection_gap(&self) -> bool;
    fn has_site(&self, node: Node<'_>) -> bool;
}

pub struct ComparisonContext<'a, P: IdentityProofs> {
    pub language: Language,
    pub owner_region: Range,
    pub source: &'a str,
    pub env: &'a EnvironmentFileResult,
    pub members: &'a P,
    pub enclosing_binders: &'a [&'a str],
}

fn allows_implicit_current_object_member(language: Language) -> bool {
    matches!(
        language,
        Language::Java
            | Language::CSharp
            | Language::Kotlin
            | Language::Scala
            | Language::Cpp
            | Language::Ruby
    )
}

fn bare_name_resolves_to_current_member(language: Language) -> bool {
    matches!(language, Language::Java | Language::Ruby)
}

fn implicit_member_identifier_kind(language: Language) -> Option<&'static str> {
    match language {
        Language::Kotlin => Some("simple_identifier"),
        Language::Java | Language::CSharp | Language::Scala | Language::Cpp | Language::Ruby => {
            Some("identifier")
        }
        _ => None,
    }
}

fn transparent_wrapper_child<'tree>(node: Node<'tree>, kinds: &[&str]) -> Option<Node<'tree>> {
    (kinds.contains(&node.kind()) && node.named_child_count() == 1)
        .then(|| node.named_child(0))
        .flatten()
}

fn receiver_member_parts(node: Node<'_>, language: Language) -> Option<(Node<'_>, Node<'_>)> {
    let (kind, receiver_field, member_field) = match language {
        Language::Java => ("field_access", "object", "field"),
        Language::CSharp => ("member_access_expression", "expression", "name"),
        Language::Python => ("attribute", "object", "attribute"),
        Language::JavaScript | Language::TypeScript => ("member_expression", "object", "property"),
        Language::Go => ("selector_expression", "operand", "field"),
        Language::Kotlin => ("navigation_expression", "", ""),
        Language::Scala => ("field_expression", "value", "field"),
        Language::Rust => ("field_expression", "value", "field"),
        _ => return None,
    };
    if node.kind() != kind {
        return None;
    }
    if language == Language::Kotlin {
        return Some((node.named_child(0)?, node.named_child(1)?.named_child(0)?));
    }
    Some((
        node.child_by_field_name(receiver_field)?,
        node.child_by_field_name(member_field)?,
    ))
}

fn type_qualified_receiver<P: IdentityProofs>(
    receiver: Node<'_>,
    source: &str,
    env: &EnvironmentFileResult,
    members: &P,
) -> bool {
    if receiver.kind() == "type_identifier" {
        return true;
    }
    if members
        .target_at(receiver)
        .is_ok_and(|target| target.kind() == CodeUnitType::Class)
    {
        return true;
    }
    source.get(receiver.byte_range()).is_some_and(|name| {
        matches!(
            binding_of(env, name, receiver.start_byte(), Some(Namespace::Type)),
            BindingOfOutcome::Reached(_) | BindingOfOutcome::Shadowed { .. }
        )
    })
}

fn nearest_current_object_owner<'tree, B: IdentityBudget>(
    site: Node<'tree>,
    language: Language,
    budget: &mut B,
) -> Result<Option<(Node<'tree>, CurrentObjectOwner)>, IdentityOpenReason> {
    let support = language_support_for_hook(language, "structural_identity_owner");
    let mut ancestor = site.parent();
    while let Some(node) = ancestor {
        budget.step()?;
        if let Some(owner) = support.and_then(|hook| hook.identity_current_object_owner(node)) {
            return Ok(Some((node, owner)));
        }
        ancestor = node.parent();
    }
    Ok(None)
}

fn qualifier_is_enclosing_type<P: IdentityProofs, B: IdentityBudget>(
    qualifier: Node<'_>,
    site: Node<'_>,
    language: Language,
    source: &str,
    env: &EnvironmentFileResult,
    members: &P,
    budget: &mut B,
) -> Result<bool, IdentityOpenReason> {
    let simple_name = match qualifier.kind() {
        "identifier" | "type_identifier" | "simple_identifier" => qualifier,
        "generic_name" => match qualifier.named_child(0) {
            Some(name) if name.kind() == "identifier" => name,
            _ => return Ok(false),
        },
        _ => return Ok(false),
    };
    let Some((owner, CurrentObjectOwner::NamedSelfType)) =
        nearest_current_object_owner(site, language, budget)?
    else {
        return Ok(false);
    };
    let Some(owner_name) = owner.child_by_field_name("name") else {
        return Ok(false);
    };
    let Some(spelling) = source.get(simple_name.byte_range()) else {
        return Ok(false);
    };
    if source.get(owner_name.byte_range()) != Some(spelling) {
        return Ok(false);
    }
    let exact_target = members.target_at(qualifier).is_ok_and(|target| {
        target.kind() == CodeUnitType::Class
            && target.source() == &env.scopes[0].file
            && target.terminal_name() == spelling
    });
    // In Java and C#, the unique immediately enclosing declaration binds its
    // own simple type name inside the body. The lexical environment records
    // type parameters, not the enclosing class declaration itself.
    let lexical_self_type = matches!(language, Language::Java | Language::CSharp)
        || (language == Language::Scala && owner.kind() == "object_definition")
        || (language == Language::Kotlin && owner.kind() == "object_declaration");
    if !exact_target && !lexical_self_type {
        return Ok(false);
    }

    let parameters = (0..owner.named_child_count())
        .filter_map(|i| owner.named_child(i))
        .find(|child| matches!(child.kind(), "type_parameter_list" | "type_parameters"));
    match parameters {
        None => {
            if qualifier != simple_name {
                return Ok(false);
            }
        }
        Some(parameters) => {
            let Some(arguments) = (0..qualifier.named_child_count())
                .filter_map(|i| qualifier.named_child(i))
                .find(|child| matches!(child.kind(), "type_argument_list" | "type_arguments"))
            else {
                return Ok(false);
            };
            if parameters.named_child_count() != arguments.named_child_count() {
                return Ok(false);
            }
            for i in 0..parameters.named_child_count() {
                budget.step()?;
                let Some(parameter) = parameters.named_child(i) else {
                    return Ok(false);
                };
                let Some(argument) = arguments.named_child(i) else {
                    return Ok(false);
                };
                let parameter_name = parameter
                    .child_by_field_name("name")
                    .or_else(|| parameter.named_child(0))
                    .unwrap_or(parameter);
                if source.get(parameter_name.byte_range()) != source.get(argument.byte_range()) {
                    return Ok(false);
                }
            }
        }
    }

    // A source file may contain different nested or namespace-qualified types
    // with the same simple name. Uniqueness in this file ties the exact target
    // proof to this parsed declaration without guessing an owner from spelling.
    let mut root = owner;
    while let Some(parent) = root.parent() {
        budget.step()?;
        root = parent;
    }
    let mut pending = vec![root];
    let mut matching_declarations = 0;
    while let Some(node) = pending.pop() {
        budget.step()?;
        if node.kind() == owner.kind()
            && node
                .child_by_field_name("name")
                .and_then(|name| source.get(name.byte_range()))
                == Some(spelling)
        {
            matching_declarations += 1;
            if matching_declarations > 1 {
                return Ok(false);
            }
        }
        for i in 0..node.named_child_count() {
            if let Some(child) = node.named_child(i) {
                pending.push(child);
            }
        }
    }
    Ok(matching_declarations == 1)
}

fn lookup_introducing_declaration(node: Node<'_>, policy: ReceiverLookupPolicy) -> bool {
    match policy {
        ReceiverLookupPolicy::CSharpUsings => node.kind() == "using_directive",
        ReceiverLookupPolicy::KotlinExtensions => {
            matches!(node.kind(), "function_declaration" | "property_declaration")
                && (node.child_by_field_name("receiver").is_some()
                    || (0..node.named_child_count()).any(|i| {
                        node.named_child(i)
                            .is_some_and(|child| child.kind() == "receiver_type")
                    }))
        }
        ReceiverLookupPolicy::ScalaImportsImplicits => {
            matches!(node.kind(), "import_declaration" | "given_definition")
                || (matches!(
                    node.kind(),
                    "val_definition"
                        | "var_definition"
                        | "function_definition"
                        | "class_definition"
                ) && (has_direct_token(node, "implicit")
                    || (0..node.named_child_count()).any(|i| {
                        node.named_child(i).is_some_and(|child| {
                            child.kind() == "modifiers" && has_direct_token(child, "implicit")
                        })
                    })))
        }
        ReceiverLookupPolicy::RustUsesTraits => {
            matches!(node.kind(), "use_declaration" | "trait_item")
        }
        _ => false,
    }
}

fn same_member_lookup_scope<B: IdentityBudget>(
    left: Node<'_>,
    right: Node<'_>,
    policy: ReceiverLookupPolicy,
    budget: &mut B,
) -> Result<bool, IdentityOpenReason> {
    if policy == ReceiverLookupPolicy::ReceiverOnly {
        return Ok(true);
    }
    if policy == ReceiverLookupPolicy::ProofRequired {
        return Ok(false);
    }
    let mut seen = HashSet::new();
    for site in [left, right] {
        let mut ancestor = site.parent();
        while let Some(scope) = ancestor {
            budget.step()?;
            let contains_both = scope.start_byte() <= left.start_byte()
                && left.end_byte() <= scope.end_byte()
                && scope.start_byte() <= right.start_byte()
                && right.end_byte() <= scope.end_byte();
            if seen.insert((scope.start_byte(), scope.end_byte()))
                && (!contains_both || policy == ReceiverLookupPolicy::ScalaImportsImplicits)
            {
                let mut cursor = scope.walk();
                if cursor.goto_first_child() {
                    loop {
                        budget.step()?;
                        let declaration = cursor.node();
                        if lookup_introducing_declaration(declaration, policy) {
                            let visible = |point: Node<'_>| {
                                scope.start_byte() <= point.start_byte()
                                    && point.end_byte() <= scope.end_byte()
                                    && (policy != ReceiverLookupPolicy::ScalaImportsImplicits
                                        || declaration.end_byte() <= point.start_byte())
                            };
                            if visible(left) != visible(right) {
                                return Ok(false);
                            }
                        }
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
            ancestor = scope.parent();
        }
    }
    Ok(true)
}

/// Compare two subtrees node for node.
///
/// A nested callable or local class at matching positions makes an otherwise
/// equal comparison `DeferredBody`: its shape is still compared, so a
/// syntactic difference inside it remains `Distinct`, but its names are not,
/// because its own parameters and locals bind per closure and its captures are
/// not modeled.
pub fn compare_trees<P: IdentityProofs, B: IdentityBudget>(
    earlier: Node<'_>,
    later: Node<'_>,
    context: &ComparisonContext<'_, P>,
    budget: &mut B,
) -> IdentityVerdict {
    if let Err(reason) = budget.charge_comparison() {
        return IdentityVerdict::Open(reason);
    }
    let language = context.language;
    let owner_region = context.owner_region;
    let source = context.source;
    let env = context.env;
    let members = context.members;
    let enclosing_binders = context.enclosing_binders;
    let support = language_support_for_hook(language, "structural_identity");
    let current_object_fields = support.and_then(|support| support.branch_current_object_fields());
    let wrapper_kinds = support.map_or(&[][..], |support| {
        support.identity_transparent_wrapper_kinds()
    });
    let receiver_lookup = support.map_or(ReceiverLookupPolicy::ProofRequired, |support| {
        support.identity_receiver_lookup()
    });
    // The flag records whether the pair lies inside a nested callable.
    let mut stack = vec![(earlier, later, false)];
    let mut renamed = HashMap::<usize, usize>::new();
    let mut reverse_renamed = HashMap::<usize, usize>::new();
    // Reads resolve after every subtree-local binder is paired, so a read that
    // precedes its binder in source order, such as a comprehension element,
    // still sees the pairing.
    let mut reads = Vec::new();
    let mut receiver_determined_members = HashSet::new();
    let mut deferred = false;
    let mut visited = 0;
    while let Some((left, right, nested)) = stack.pop() {
        if let Err(reason) = budget.step() {
            return IdentityVerdict::Open(reason);
        }
        visited += 1;
        if visited > MAX_COMPARISON_TREE_NODES {
            return IdentityVerdict::Open(IdentityOpenReason::ComparisonBudget);
        }
        if left.has_error() || right.has_error() || left.is_missing() || right.is_missing() {
            return IdentityVerdict::Open(IdentityOpenReason::SyntaxRecovery);
        }
        // Ruby `then` and `else` are statement lists; only
        // their statements are compared.
        let ruby_statement_list = |node: Node<'_>| matches!(node.kind(), "then" | "else");
        if language == Language::Ruby && ruby_statement_list(left) && ruby_statement_list(right) {
            if left.child_count() > MAX_COMPARISON_TREE_NODES
                || right.child_count() > MAX_COMPARISON_TREE_NODES
                || stack.len() + left.child_count() > MAX_COMPARISON_TREE_NODES
            {
                return IdentityVerdict::Open(IdentityOpenReason::ComparisonBudget);
            }
            let left_statements = match bounded_named_statements(left, stack.len(), budget) {
                Ok(children) => children,
                Err(reason) => return IdentityVerdict::Open(reason),
            };
            let right_statements = match bounded_named_statements(right, stack.len(), budget) {
                Ok(children) => children,
                Err(reason) => return IdentityVerdict::Open(reason),
            };
            if left_statements.len() != right_statements.len() {
                return IdentityVerdict::Distinct;
            }
            stack.extend(
                left_statements
                    .into_iter()
                    .zip(right_statements)
                    .rev()
                    .map(|(left, right)| (left, right, nested)),
            );
            continue;
        }
        // A one-expression wrapper has no independent value or binding. Peel
        // it on either side before comparing kinds and reference identities.
        if left.kind() != right.kind() {
            if let Some(inner) = transparent_wrapper_child(left, wrapper_kinds) {
                stack.push((inner, right, nested));
                continue;
            }
            if let Some(inner) = transparent_wrapper_child(right, wrapper_kinds) {
                stack.push((left, inner, nested));
                continue;
            }
        }
        if !nested
            && let Some(spec) = current_object_fields.as_ref()
            && let (Some(left_member), Some(right_member)) = (spec.member(left), spec.member(right))
            && members.same_storage_field(left_member, right_member)
        {
            // Both receivers denote this object, and both strict targets name
            // the same physical storage slot. Presentation identity alone does
            // not justify this equality; properties and methods never enter it.
            continue;
        }
        if !nested
            && let Some(spec) = current_object_fields.as_ref()
            && let (Some((left_receiver, left_member)), Some((right_receiver, right_member))) = (
                spec.receiver_and_member(left),
                spec.receiver_and_member(right),
            )
            && (left_receiver.kind() == spec.parent_kind
                || right_receiver.kind() == spec.parent_kind)
            && source.get(left_member.byte_range()) == source.get(right_member.byte_range())
        {
            return if members.has_storage_field(left_member)
                && members.has_storage_field(right_member)
            {
                IdentityVerdict::Distinct
            } else {
                IdentityVerdict::Open(IdentityOpenReason::MemberResolutionUnavailable)
            };
        }
        if left.kind() != right.kind() {
            if !nested
                && let Some(spec) = current_object_fields.as_ref()
                && let Some((member, bare)) =
                    [(left, right), (right, left)]
                        .into_iter()
                        .find_map(|(access, bare)| {
                            (bare.kind() == implicit_member_identifier_kind(language)?)
                                .then(|| {
                                    spec.current_member(access)
                                        .or_else(|| {
                                            (language == Language::CSharp)
                                                .then(|| receiver_member_parts(access, language))
                                                .flatten()
                                                .and_then(|(receiver, member)| {
                                                    (receiver.kind() == spec.current_kind)
                                                        .then_some(member)
                                                })
                                        })
                                        .map(|member| (member, bare))
                                })
                                .flatten()
                        })
                && let Some(name) = source.get(bare.byte_range())
                && source.get(member.byte_range()) == Some(name)
            {
                if !allows_implicit_current_object_member(language) {
                    return IdentityVerdict::Distinct;
                }
                return match binding_of(env, name, bare.start_byte(), Some(Namespace::Value)) {
                    BindingOfOutcome::Incomplete(_) => {
                        IdentityVerdict::Open(IdentityOpenReason::LexicalBindingUnavailable)
                    }
                    BindingOfOutcome::Reached(index)
                    | BindingOfOutcome::Shadowed { winner: index, .. }
                        if matches!(
                            env.bindings[index].kind,
                            BindingKind::Local
                                | BindingKind::Parameter
                                | BindingKind::PatternBinder
                                | BindingKind::LoopVariable
                                | BindingKind::CatchOrResource
                                | BindingKind::ImportBinder
                                | BindingKind::TypeParameter
                        ) =>
                    {
                        IdentityVerdict::Distinct
                    }
                    BindingOfOutcome::Reached(_)
                    | BindingOfOutcome::Shadowed { .. }
                    | BindingOfOutcome::NoBinding => {
                        if members.same_storage_field(member, bare) {
                            continue;
                        }
                        if bare_name_resolves_to_current_member(language) {
                            continue;
                        }
                        if language == Language::CSharp
                            && (support.is_some_and(|hook| {
                                hook.identity_current_instance_member(member, source)
                            }) || matches!(
                                (members.target_at(member), members.target_at(bare)),
                                (Ok(a), Ok(b)) if a == b
                                    && matches!(a.kind(), CodeUnitType::Field | CodeUnitType::Function)
                            ))
                        {
                            continue;
                        }
                        IdentityVerdict::Open(IdentityOpenReason::MemberResolutionUnavailable)
                    }
                };
            }
            // A type-qualified static member may also be addressed by a bare
            // name, but only the immediately enclosing type can establish it.
            if !nested
                && allows_implicit_current_object_member(language)
                && let Some(spec) = current_object_fields.as_ref()
                && let Some((access, bare)) =
                    [(left, right), (right, left)]
                        .into_iter()
                        .find(|(access, bare)| {
                            access.kind() == spec.access_kind
                                && Some(bare.kind()) == implicit_member_identifier_kind(language)
                        })
                && let Some((receiver, member)) = spec.receiver_and_member(access)
                && let Some(name) = source.get(bare.byte_range())
                && source.get(member.byte_range()) == Some(name)
                && receiver.kind() != spec.parent_kind
                && let Some(qualifier) = source.get(receiver.byte_range())
            {
                match nearest_current_object_owner(access, language, budget) {
                    Ok(Some((_, CurrentObjectOwner::Other))) => {
                        return IdentityVerdict::Open(
                            IdentityOpenReason::MemberResolutionUnavailable,
                        );
                    }
                    Err(reason) => return IdentityVerdict::Open(reason),
                    _ => {}
                }
                let bare_binding = binding_of(env, name, bare.start_byte(), Some(Namespace::Value));
                if let BindingOfOutcome::Reached(index)
                | BindingOfOutcome::Shadowed { winner: index, .. } = bare_binding
                    && matches!(
                        env.bindings[index].kind,
                        BindingKind::Local
                            | BindingKind::Parameter
                            | BindingKind::PatternBinder
                            | BindingKind::LoopVariable
                            | BindingKind::CatchOrResource
                            | BindingKind::ImportBinder
                            | BindingKind::TypeParameter
                    )
                {
                    return IdentityVerdict::Distinct;
                }
                if matches!(bare_binding, BindingOfOutcome::Incomplete(_)) {
                    return IdentityVerdict::Open(IdentityOpenReason::LexicalBindingUnavailable);
                }
                if let BindingOfOutcome::Reached(index)
                | BindingOfOutcome::Shadowed { winner: index, .. } = binding_of(
                    env,
                    qualifier,
                    receiver.start_byte(),
                    Some(Namespace::Value),
                ) && matches!(
                    env.bindings[index].kind,
                    BindingKind::Local
                        | BindingKind::Parameter
                        | BindingKind::PatternBinder
                        | BindingKind::LoopVariable
                        | BindingKind::CatchOrResource
                ) {
                    return IdentityVerdict::Distinct;
                }
                match qualifier_is_enclosing_type(
                    receiver, access, language, source, env, members, budget,
                ) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(reason) => return IdentityVerdict::Open(reason),
                }
                return IdentityVerdict::Open(IdentityOpenReason::MemberResolutionUnavailable);
            }
            return IdentityVerdict::Distinct;
        }
        let nested_callable = is_nested_callable(left, language);
        let php_exact_callable =
            language == Language::Php && php_exact_nested_callable(left, right);
        let scala_exact_callable = if language == Language::Scala {
            match scala_nested_callable_is_exact(left, right, env, budget) {
                Ok(exact) => exact,
                Err(reason) if budget.exhausted() => return IdentityVerdict::Open(reason),
                // A local refusal cannot make a closure exact. Keep comparing
                // outer syntax so an independent difference can still refute it.
                Err(_) => false,
            }
        } else {
            false
        };
        let nested = nested || (nested_callable && !(php_exact_callable || scala_exact_callable));
        deferred |= nested;
        if position_dependent(left, language, source) || position_dependent(right, language, source)
        {
            return IdentityVerdict::Distinct;
        }
        if let (Some((left_receiver, left_member)), Some((right_receiver, right_member))) = (
            receiver_member_parts(left, language),
            receiver_member_parts(right, language),
        ) && source.get(left_member.byte_range()).is_some()
            && source.get(left_member.byte_range()) == source.get(right_member.byte_range())
            && !current_object_fields.as_ref().is_some_and(|spec| {
                left_receiver.kind() == spec.parent_kind
                    || right_receiver.kind() == spec.parent_kind
            })
        {
            if source.get(left_receiver.byte_range()) != source.get(right_receiver.byte_range())
                && (type_qualified_receiver(left_receiver, source, env, members)
                    || type_qualified_receiver(right_receiver, source, env, members))
            {
                return IdentityVerdict::Open(IdentityOpenReason::MemberResolutionUnavailable);
            }
            let scope_matches = match same_member_lookup_scope(left, right, receiver_lookup, budget)
            {
                Ok(matches) => matches,
                Err(reason) => return IdentityVerdict::Open(reason),
            };
            if !scope_matches {
                return IdentityVerdict::Open(IdentityOpenReason::MemberResolutionUnavailable);
            }
            if receiver_lookup != ReceiverLookupPolicy::ProofRequired {
                match (
                    members.target_at(left_member),
                    members.target_at(right_member),
                ) {
                    (Ok(a), Ok(b)) if a != b => return IdentityVerdict::Distinct,
                    _ => {}
                }
                receiver_determined_members.insert((left_member.id(), right_member.id()));
            }
        }
        if left.kind() == "field_access" {
            let (Some(left_field), Some(right_field), Some(left_object), Some(right_object)) = (
                left.child_by_field_name("field"),
                right.child_by_field_name("field"),
                left.child_by_field_name("object"),
                right.child_by_field_name("object"),
            ) else {
                return IdentityVerdict::Open(IdentityOpenReason::MissingField);
            };
            if !same_member(left_field, right_field, source, members) {
                return IdentityVerdict::Distinct;
            }
            stack.push((left_object, right_object, nested));
            continue;
        }
        if language == Language::Java && left.kind() == "method_invocation" {
            if left.child_count() > MAX_COMPARISON_TREE_NODES
                || right.child_count() > MAX_COMPARISON_TREE_NODES
                || stack.len() + left.child_count() > MAX_COMPARISON_TREE_NODES
            {
                return IdentityVerdict::Open(IdentityOpenReason::ComparisonBudget);
            }
            let (Some(left_name), Some(right_name)) = (
                left.child_by_field_name("name"),
                right.child_by_field_name("name"),
            ) else {
                return IdentityVerdict::Open(IdentityOpenReason::MissingField);
            };
            if !same_member(left_name, right_name, source, members) {
                return IdentityVerdict::Distinct;
            }
            let mut left_children = match bounded_non_extra_children(left, stack.len(), budget) {
                Ok(children) => children,
                Err(reason) => return IdentityVerdict::Open(reason),
            }
            .into_iter()
            .filter(|(field, _)| *field != Some("name"))
            .collect::<Vec<_>>();
            let mut right_children = match bounded_non_extra_children(right, stack.len(), budget) {
                Ok(children) => children,
                Err(reason) => return IdentityVerdict::Open(reason),
            }
            .into_iter()
            .filter(|(field, _)| *field != Some("name"))
            .collect::<Vec<_>>();
            // Java method invocation uses the method namespace. A local or
            // parameter of the same name does not shadow a method call.
            let left_this = explicit_this_receiver(left);
            let right_this = explicit_this_receiver(right);
            let left_implicit = left.child_by_field_name("object").is_none();
            let right_implicit = right.child_by_field_name("object").is_none();
            if (left_this && right_implicit) || (right_this && left_implicit) {
                for children in [&mut left_children, &mut right_children] {
                    children
                        .retain(|(field, child)| *field != Some("object") && child.kind() != ".");
                }
            }
            if left_children.len() != right_children.len() {
                return IdentityVerdict::Distinct;
            }
            for ((left_field, left_child), (right_field, right_child)) in
                left_children.into_iter().zip(right_children).rev()
            {
                if left_field != right_field {
                    return IdentityVerdict::Distinct;
                }
                stack.push((left_child, right_child, nested));
            }
            continue;
        }
        if left.child_count() > MAX_COMPARISON_TREE_NODES
            || right.child_count() > MAX_COMPARISON_TREE_NODES
            || stack.len() + left.child_count() > MAX_COMPARISON_TREE_NODES
        {
            return IdentityVerdict::Open(IdentityOpenReason::ComparisonBudget);
        }
        let left_children = match bounded_non_extra_children(left, stack.len(), budget) {
            Ok(children) => children,
            Err(reason) => return IdentityVerdict::Open(reason),
        };
        let right_children = match bounded_non_extra_children(right, stack.len(), budget) {
            Ok(children) => children,
            Err(reason) => return IdentityVerdict::Open(reason),
        };
        if left_children.len() != right_children.len() {
            return IdentityVerdict::Distinct;
        }
        if !left_children.is_empty() {
            for ((left_field, left_child), (right_field, right_child)) in
                left_children.into_iter().zip(right_children).rev()
            {
                if left_field != right_field {
                    return IdentityVerdict::Distinct;
                }
                stack.push((left_child, right_child, nested));
            }
            continue;
        }
        if receiver_determined_members.contains(&(left.id(), right.id())) {
            if source.get(left.byte_range()) != source.get(right.byte_range()) {
                return IdentityVerdict::Distinct;
            }
            continue;
        }
        let is_name = matches!(
            left.kind(),
            "identifier"
                | "simple_identifier"
                | "type_identifier"
                | "shorthand_property_identifier"
                | "shorthand_property_identifier_pattern"
        );
        // A name inside a nested callable may be one of its own binders, so
        // it neither proves nor refutes the comparison, which is deferred.
        if nested && is_name {
            continue;
        }
        let (Some(name), Some(other_name)) = (
            source.get(left.byte_range()),
            source.get(right.byte_range()),
        ) else {
            return IdentityVerdict::Open(IdentityOpenReason::SyntaxRecovery);
        };
        if matches!(
            left.kind(),
            "identifier" | "simple_identifier" | "shorthand_property_identifier_pattern"
        ) {
            // A declaration inside each subtree is a pair of distinct bindings
            // that stand for each other, like a block local in each subtree.
            let binder_at = |node: Node<'_>, spelling: &str, subtree: Node<'_>| {
                env.bindings_named(spelling).iter().copied().find(|index| {
                    let range = env.bindings[*index].range;
                    range.start_byte == node.start_byte()
                        && range.end_byte == node.end_byte()
                        && (subtree_local_binding(env, *index, subtree)
                            || (language == Language::Scala
                                && subtree_callable_binding(env, *index, subtree)))
                })
            };
            match (
                binder_at(left, name, earlier),
                binder_at(right, other_name, later),
            ) {
                (Some(a), Some(b)) => {
                    if env.bindings[a].kind != env.bindings[b].kind
                        || env.bindings[a].hoisting != env.bindings[b].hoisting
                    {
                        return IdentityVerdict::Open(
                            IdentityOpenReason::LexicalBindingUnavailable,
                        );
                    }
                    // A shorthand pattern's spelling is also the property it
                    // destructures.
                    if left.kind() == "shorthand_property_identifier_pattern" && name != other_name
                    {
                        return IdentityVerdict::Distinct;
                    }
                    if renamed.insert(a, b).is_some_and(|prior| prior != b)
                        || reverse_renamed.insert(b, a).is_some_and(|prior| prior != a)
                    {
                        return IdentityVerdict::Open(
                            IdentityOpenReason::LexicalBindingUnavailable,
                        );
                    }
                    continue;
                }
                (Some(_), None) | (None, Some(_)) => {
                    return IdentityVerdict::Open(IdentityOpenReason::LexicalBindingUnavailable);
                }
                (None, None) => {}
            }
        }
        if matches!(left.kind(), "identifier" | "simple_identifier") {
            let roles = identifier_role(left, budget).and_then(|left_role| {
                identifier_role(right, budget).map(|right_role| (left_role, right_role))
            });
            let roles = match roles {
                Ok(roles) => roles,
                Err(reason) => return IdentityVerdict::Open(reason),
            };
            match roles {
                // A declaration the environment does not place inside its subtree.
                (IdentifierRole::Binder, IdentifierRole::Binder) => {
                    return IdentityVerdict::Open(IdentityOpenReason::LexicalBindingUnavailable);
                }
                (IdentifierRole::Value, IdentifierRole::Value) => reads.push((left, right)),
                // A property, attribute, label or type name at matching
                // positions is the same structured name.
                (IdentifierRole::NonValue, IdentifierRole::NonValue) => {
                    if name != other_name {
                        return IdentityVerdict::Distinct;
                    }
                }
                (IdentifierRole::NonValue, _) | (_, IdentifierRole::NonValue) => {
                    return IdentityVerdict::Open(IdentityOpenReason::NonLocalReference);
                }
                _ => return IdentityVerdict::Distinct,
            }
        } else if left.is_named() && name != other_name {
            return IdentityVerdict::Distinct;
        }
    }
    for (left, right) in reads {
        if let Err(reason) = budget.step() {
            return IdentityVerdict::Open(reason);
        }
        let (Some(name), Some(other_name)) = (
            source.get(left.byte_range()),
            source.get(right.byte_range()),
        ) else {
            return IdentityVerdict::Open(IdentityOpenReason::SyntaxRecovery);
        };
        // A Ruby assignment target is its own binder: the environment starts
        // that binding after the assignment, so a lookup at the target would
        // find an earlier assignment's row or nothing.
        let resolve = |node: Node<'_>, spelling: &str| {
            let own = (language == Language::Ruby)
                .then(|| {
                    env.bindings_named(spelling).iter().copied().find(|index| {
                        let range = env.bindings[*index].range;
                        range.start_byte == node.start_byte() && range.end_byte == node.end_byte()
                    })
                })
                .flatten();
            match own {
                Some(index) => BindingOfOutcome::Reached(index),
                None => binding_of(env, spelling, node.start_byte(), Some(Namespace::Value)),
            }
        };
        let (a, b) = match (resolve(left, name), resolve(right, other_name)) {
            (BindingOfOutcome::Reached(a), BindingOfOutcome::Reached(b)) => (a, b),
            (
                BindingOfOutcome::Shadowed { winner: a, .. },
                BindingOfOutcome::Shadowed { winner: b, .. },
            ) => (a, b),
            (BindingOfOutcome::Reached(a), BindingOfOutcome::Shadowed { winner: b, .. })
            | (BindingOfOutcome::Shadowed { winner: a, .. }, BindingOfOutcome::Reached(b)) => {
                (a, b)
            }
            // One unbound spelling in both subtrees is one global or member
            // lookup from the same scope, unless an enclosing condition declares
            // it with a binder the environment does not model.
            (BindingOfOutcome::NoBinding, BindingOfOutcome::NoBinding) if name == other_name => {
                if enclosing_binders.contains(&name) {
                    return IdentityVerdict::Open(IdentityOpenReason::LexicalBindingUnavailable);
                }
                continue;
            }
            (BindingOfOutcome::NoBinding, BindingOfOutcome::NoBinding)
                if members.has_collection_gap()
                    || members.has_site(left)
                    || members.has_site(right) =>
            {
                // Exact resolver targets may distinguish nonlocal operations,
                // even when constants have equal values. Equal presentation
                // CodeUnits can hide different canonical declarations, so they
                // never establish a new equality proof. Distinction grants
                // no stability privilege, including in conditions.
                return match (members.target_at(left), members.target_at(right)) {
                    (Ok(a), Ok(b)) if a != b => IdentityVerdict::Distinct,
                    (Ok(_), Ok(_)) => IdentityVerdict::Open(IdentityOpenReason::NonLocalReference),
                    (Err(reason), _) | (_, Err(reason)) => IdentityVerdict::Open(reason),
                };
            }
            (BindingOfOutcome::NoBinding, _) | (_, BindingOfOutcome::NoBinding) => {
                return IdentityVerdict::Open(IdentityOpenReason::NonLocalReference);
            }
            (BindingOfOutcome::Incomplete(_), _) | (_, BindingOfOutcome::Incomplete(_)) => {
                return IdentityVerdict::Open(IdentityOpenReason::LexicalBindingUnavailable);
            }
        };
        // A pattern binder that an enclosing condition declares, such as Java's
        // flow-sensitive pattern variable, is in effect in some regions only and
        // is not represented by the shared lexical environment. Rust's
        // `if let` binders are represented with their exact consequence-body
        // interval by the Rust adapter, so the Rust branch below can compare
        // the pattern binding with an outer binding precisely.
        let declared_by_condition = |index: usize| {
            let range = env.bindings[index].range;
            let within =
                |start: usize, end: usize| start <= range.start_byte && range.end_byte <= end;
            env.bindings[index].kind == BindingKind::PatternBinder
                && within(owner_region.start_byte, owner_region.end_byte)
                && !within(earlier.start_byte(), earlier.end_byte())
                && !within(later.start_byte(), later.end_byte())
        };
        if language != Language::Rust && (declared_by_condition(a) || declared_by_condition(b)) {
            return IdentityVerdict::Open(IdentityOpenReason::LexicalBindingUnavailable);
        }
        // Every assignment to a Ruby local is a binding row of its own, but
        // all of them in one method are the same variable. In valid Go, two
        // declarations of one name in one block are a `:=` redeclaration,
        // which assigns the existing variable.
        if matches!(language, Language::Ruby | Language::Go)
            && name == other_name
            && env.bindings[a].kind == BindingKind::Local
            && env.bindings[b].kind == BindingKind::Local
            && env.bindings[a].declaring_scope == env.bindings[b].declaring_scope
        {
            continue;
        }
        if let Some(mapped) = renamed.get(&a) {
            if *mapped != b {
                return IdentityVerdict::Distinct;
            }
            continue;
        }
        if reverse_renamed.contains_key(&b) {
            return IdentityVerdict::Distinct;
        }
        if a != b
            && (subtree_local_binding(env, a, earlier) || subtree_local_binding(env, b, later))
        {
            return IdentityVerdict::Open(IdentityOpenReason::LexicalBindingUnavailable);
        }
        if language == Language::Rust
            && (env.bindings[a].kind == BindingKind::PatternBinder
                || env.bindings[b].kind == BindingKind::PatternBinder)
        {
            if a == b && name == other_name {
                continue;
            }
            return IdentityVerdict::Distinct;
        }
        if !ordinary_binding(env, a) || !ordinary_binding(env, b) {
            if a == b && name == other_name {
                continue;
            }
            return IdentityVerdict::Open(IdentityOpenReason::NonLocalReference);
        }
        if a != b || name != other_name {
            return IdentityVerdict::Distinct;
        }
    }
    if deferred {
        IdentityVerdict::Open(IdentityOpenReason::DeferredBody)
    } else {
        IdentityVerdict::Identical
    }
}

/// Whether `node` evaluates to its own source position, so two spellings of
/// it at different positions are different values: Rust's `line!()` and
/// `column!()`, PHP's case-insensitive `__LINE__` and Ruby's `__LINE__`.
pub(super) fn position_dependent(node: Node<'_>, language: Language, source: &str) -> bool {
    match language {
        Language::Php => {
            return node.kind() == "name"
                && source
                    .get(node.byte_range())
                    .is_some_and(|name| name.eq_ignore_ascii_case("__LINE__"));
        }
        // Ruby uses an identifier in expressions and a `line` token in patterns.
        Language::Ruby => {
            return node.kind() == "line"
                || (node.kind() == "identifier"
                    && source.get(node.byte_range()) == Some("__LINE__"));
        }
        // `__LINE__` and `__COUNTER__` are macros the preprocessor replaces
        // with the line and a running count.
        Language::Cpp => {
            return node.kind() == "identifier"
                && matches!(
                    source.get(node.byte_range()),
                    Some("__LINE__" | "__COUNTER__")
                );
        }
        Language::Rust => {}
        _ => return false,
    }
    if node.kind() != "macro_invocation" {
        return false;
    }
    let Some(mut name) = node.child_by_field_name("macro") else {
        return false;
    };
    if name.kind() == "scoped_identifier"
        && let Some(last) = name.child_by_field_name("name")
    {
        name = last;
    }
    matches!(source.get(name.byte_range()), Some("line" | "column"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum IdentifierRole {
    Value,
    Binder,
    NonValue,
}

pub(super) fn identifier_role<B: IdentityBudget>(
    node: Node<'_>,
    budget: &mut B,
) -> Result<IdentifierRole, IdentityOpenReason> {
    let Some(parent) = node.parent() else {
        return Ok(IdentifierRole::NonValue);
    };
    if parent.child_count() > MAX_COMPARISON_TREE_NODES {
        return Err(IdentityOpenReason::ComparisonBudget);
    }
    let mut field = None;
    let mut cursor = parent.walk();
    if cursor.goto_first_child() {
        loop {
            budget.step()?;
            if cursor.node() == node {
                field = Some(cursor.field_name());
                break;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    if matches!(
        parent.kind(),
        "jsx_opening_element" | "jsx_closing_element" | "jsx_self_closing_element"
    ) {
        return Ok(IdentifierRole::NonValue);
    }
    if parent.kind() == "method_invocation" && field.flatten() != Some("object") {
        return Ok(IdentifierRole::NonValue);
    }
    // Kotlin spells no fields: a member follows `.` in a navigation suffix, a
    // named argument's label precedes its `=`, and a local's name is the
    // direct child of its variable declaration.
    match parent.kind() {
        "navigation_suffix" => return Ok(IdentifierRole::NonValue),
        "value_argument" if node.next_sibling().is_some_and(|next| next.kind() == "=") => {
            return Ok(IdentifierRole::NonValue);
        }
        "variable_declaration" => return Ok(IdentifierRole::Binder),
        _ => {}
    }
    Ok(match field.flatten() {
        Some("name") if parent.kind() == "variable_declarator" => IdentifierRole::Binder,
        Some("name" | "property" | "field" | "attribute" | "key" | "type" | "label") => {
            IdentifierRole::NonValue
        }
        _ => IdentifierRole::Value,
    })
}

pub(super) fn ordinary_binding(env: &EnvironmentFileResult, index: usize) -> bool {
    matches!(
        env.bindings[index].kind,
        BindingKind::Local | BindingKind::Parameter
    )
}

/// Whether a binding is declared inside `subtree` and is in effect nowhere else:
/// a block local, a catch or resource variable, a loop variable or a
/// comprehension target. A Python assignment in a subtree binds a function
/// local, whose activation covers the whole function, so it is not subtree-local.
fn subtree_local_binding(env: &EnvironmentFileResult, index: usize, subtree: Node<'_>) -> bool {
    let binding = &env.bindings[index];
    matches!(
        binding.kind,
        BindingKind::Local
            | BindingKind::PatternBinder
            | BindingKind::LoopVariable
            | BindingKind::CatchOrResource
    ) && subtree.start_byte() <= binding.activation.start_byte
        && binding.activation.end_byte <= subtree.end_byte()
        && subtree.start_byte() <= binding.range.start_byte
        && binding.range.end_byte <= subtree.end_byte()
}

/// Scala callable parameters are separate bindings in each subtree, just like
/// subtree-local declarations. Their activation is wholly inside the subtree even
/// though the shared classifier reserves `subtree_local_binding` for declarations
/// introduced by the subtree itself.
fn subtree_callable_binding(env: &EnvironmentFileResult, index: usize, subtree: Node<'_>) -> bool {
    let binding = &env.bindings[index];
    matches!(binding.kind, BindingKind::Local | BindingKind::Parameter)
        && subtree.start_byte() <= binding.activation.start_byte
        && binding.activation.end_byte <= subtree.end_byte()
        && subtree.start_byte() <= binding.range.start_byte
        && binding.range.end_byte <= subtree.end_byte()
}

pub(super) fn bounded_named_statements<'tree, B: IdentityBudget>(
    node: Node<'tree>,
    pending: usize,
    budget: &mut B,
) -> Result<Vec<Node<'tree>>, IdentityOpenReason> {
    Ok(bounded_non_extra_children(node, pending, budget)?
        .into_iter()
        .map(|(_, child)| child)
        .filter(Node::is_named)
        .collect())
}

/// Admit each inspected child before filtering or retaining it. A bounded
/// temporary list keeps field names and source order for paired comparisons.
pub(super) fn bounded_non_extra_children<'tree, B: IdentityBudget>(
    node: Node<'tree>,
    pending: usize,
    budget: &mut B,
) -> Result<Vec<(Option<&'static str>, Node<'tree>)>, IdentityOpenReason> {
    if node.child_count() > MAX_COMPARISON_TREE_NODES
        || pending + node.child_count() > MAX_COMPARISON_TREE_NODES
    {
        return Err(IdentityOpenReason::ComparisonBudget);
    }
    let mut children = Vec::new();
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            budget.step()?;
            let child = cursor.node();
            if !child.is_extra() {
                children.push((cursor.field_name(), child));
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    Ok(children)
}

/// Whether a Java member selector at matching positions names the same member.
/// Matching trees give the selectors the same receiver and arguments, so an
/// equal spelling is the same lookup; two resolved targets can still show
/// that the lookups differ.
fn same_member<P: IdentityProofs>(
    left: Node<'_>,
    right: Node<'_>,
    source: &str,
    members: &P,
) -> bool {
    match (members.target_at(left), members.target_at(right)) {
        (Ok(a), Ok(b)) => a == b,
        _ => source.get(left.byte_range()) == source.get(right.byte_range()),
    }
}

fn explicit_this_receiver(invocation: Node<'_>) -> bool {
    invocation
        .child_by_field_name("object")
        .is_some_and(|object| object.kind() == "this")
}

/// A nested callable or local class creates a new closure or class per subtree.
/// Its captures and class identity are not modeled, so its equivalence stays
/// open rather than inferred from matching syntax. PHP is the exception for
/// by-value closures and arrows: its lexical environment gives each parameter,
/// capture and local an exact binding, so their bodies can be compared.
/// The kinds cover the Java, JavaScript, TypeScript and Python grammars; a
/// Python decorated definition is covered by the definition it wraps.
pub(super) fn is_nested_callable(node: Node<'_>, language: Language) -> bool {
    // A Ruby `block` is a closure; elsewhere a `block` is a statement block.
    if language == Language::Ruby {
        return node.is_named()
            && matches!(
                node.kind(),
                "method"
                    | "singleton_method"
                    | "block"
                    | "do_block"
                    | "lambda"
                    | "class"
                    | "module"
                    | "singleton_class"
            );
    }
    node.is_named()
        && matches!(
            node.kind(),
            // Java. `class_body` also covers an anonymous class.
            "lambda_expression"
                | "method_declaration"
                | "constructor_declaration"
                | "class_declaration"
                | "record_declaration"
                | "enum_declaration"
                | "interface_declaration"
                | "class_body"
                // JavaScript and TypeScript.
                | "function_declaration"
                | "function_expression"
                | "generator_function"
                | "generator_function_declaration"
                | "arrow_function"
                | "method_definition"
                | "class"
                | "abstract_class_declaration"
                // Python.
                | "function_definition"
                | "lambda"
                | "class_definition"
                // Rust. An async block's body runs when it is awaited.
                | "closure_expression"
                | "function_item"
                | "impl_item"
                | "trait_item"
                | "mod_item"
                | "async_block"
                // Go.
                | "func_literal"
                // C and C++, beyond the shared lambda and function kinds.
                | "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                // C#, beyond the shared lambda and class-like kinds.
                | "anonymous_method_expression"
                | "local_function_statement"
                | "struct_declaration"
                | "record_struct_declaration"
                // Kotlin, beyond the shared function, class and
                // `anonymous_function` (PHP's closure kind too) kinds.
                | "lambda_literal"
                | "object_declaration"
                | "object_literal"
                | "companion_object"
                // PHP, beyond the shared function, method, class, interface,
                // enum and arrow-function kinds.
                | "anonymous_function"
                | "anonymous_class"
                | "trait_declaration"
                // Scala, beyond the shared `lambda_expression`,
                // `function_definition` and `class_definition`. `new T { .. }`
                // is an anonymous class.
                | "object_definition"
                | "trait_definition"
                | "given_definition"
                | "instance_expression"
        )
}

/// Whether a Scala nested callable can be compared through the lexical
/// environment. Lambdas and local `def`s have environment rows for their
/// parameters and locals. An anonymous `new T { ... }` is an instance with a
/// distinct class identity, so it remains deferred even when its body text
/// matches. Deferred parameter and lazy-value shapes also retain uncertainty.
pub(super) fn scala_nested_callable_is_exact<B: IdentityBudget>(
    left: Node<'_>,
    right: Node<'_>,
    env: &EnvironmentFileResult,
    budget: &mut B,
) -> Result<bool, IdentityOpenReason> {
    if left.kind() != right.kind()
        || !matches!(left.kind(), "lambda_expression" | "function_definition")
        || !env.completeness.is_complete()
    {
        return Ok(false);
    }
    let mut stack = vec![left, right];
    let mut visited = 0;
    while let Some(node) = stack.pop() {
        budget.visit(node, &mut visited, stack.len())?;
        if node.has_error() || node.is_missing() {
            return Ok(false);
        }
        if matches!(
            node.kind(),
            "by_name_type"
                | "lazy_parameter_type"
                | "repeated_parameter_type"
                | "lazy_modifier"
                | "lazy"
        ) {
            return Ok(false);
        }
        stack.extend(
            bounded_non_extra_children(node, stack.len(), budget)?
                .into_iter()
                .map(|(_, child)| child),
        );
    }
    Ok(true)
}

fn php_exact_nested_callable(left: Node<'_>, right: Node<'_>) -> bool {
    if left.kind() != right.kind() {
        return false;
    }
    match left.kind() {
        "arrow_function" => true,
        "anonymous_function" => {
            !php_callable_has_by_ref_capture(left) && !php_callable_has_by_ref_capture(right)
        }
        _ => false,
    }
}

pub(super) fn php_callable_has_by_ref_capture(node: Node<'_>) -> bool {
    if node.kind() != "anonymous_function" {
        return false;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "anonymous_function_use_clause")
        .any(|use_clause| {
            has_direct_token(use_clause, "by_ref")
                || has_direct_token(use_clause, "reference_modifier")
                || has_direct_token(use_clause, "&")
        })
}
