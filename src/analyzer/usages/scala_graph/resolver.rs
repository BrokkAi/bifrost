use super::inverted::{CachedCallableAlternatives, is_package_level_type};
use crate::analyzer::scala::scala_import_path;
use crate::analyzer::usages::scala_graph::syntax::{ScalaCallableRole, parenthesized_arity};
use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, ProjectFile, ScalaAnalyzer, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TargetKind {
    Type,
    Constructor,
    Method,
    Field,
}

pub(super) struct TargetSpec {
    pub(super) target: CodeUnit,
    pub(super) kind: TargetKind,
    pub(super) owner: Option<CodeUnit>,
    pub(super) owner_name: Option<String>,
    pub(super) family_owners: Vec<CodeUnit>,
    pub(super) receiver_owners: Vec<CodeUnit>,
    pub(super) member_name: String,
    pub(super) target_fq_name: String,
    pub(super) owner_fq_name: Option<String>,
    pub(super) arity: Option<usize>,
    pub(super) callable_alternatives: CachedCallableAlternatives,
    pub(super) is_extension_method: bool,
    pub(super) accepts_field_implementation: bool,
    pub(super) is_object_type: bool,
    pub(super) accepts_apply_role: bool,
    pub(super) type_parent: Option<CodeUnit>,
    pub(super) accepts_companion_apply_syntax: bool,
}

impl TargetSpec {
    pub(super) fn from_target(scala: &ScalaAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() || scala.is_type_alias(target) {
            let owner_name = scala_display_name(target);
            let is_type_alias = scala.is_type_alias(target);
            let is_object_type = !is_type_alias && target.short_name().ends_with('$');
            let types = scala.project_types();
            let accepts_apply_role =
                !is_type_alias && types.class_accepts_apply_role(scala, target);
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner: Some(target.clone()),
                family_owners: vec![target.clone()],
                receiver_owners: vec![target.clone()],
                member_name: owner_name.clone(),
                target_fq_name: scala_normalized_fq_name(&target.fq_name()),
                owner_fq_name: Some(scala_normalized_fq_name(&target.fq_name())),
                owner_name: Some(owner_name),
                arity: None,
                callable_alternatives: Arc::new(Vec::new()),
                is_extension_method: false,
                accepts_field_implementation: false,
                is_object_type,
                accepts_apply_role,
                type_parent: scala.structural_parent_of(target),
                accepts_companion_apply_syntax: false,
            });
        }

        let owner = owner_of(scala, target);
        let owner_name = owner.as_ref().map(scala_display_name);
        let arity = target.signature().and_then(signature_arity).or_else(|| {
            scala
                .signatures(target)
                .into_iter()
                .find_map(|sig| signature_arity(&sig))
        });
        let callable_alternatives = if !target.is_field() && target.is_function() {
            scala
                .project_types()
                .effective_callable_alternatives_for(scala, target)
        } else {
            Arc::new(Vec::new())
        };
        let has_constructor_role = callable_alternatives.iter().any(|alternative| {
            matches!(
                alternative.role,
                ScalaCallableRole::PrimaryConstructor | ScalaCallableRole::SecondaryConstructor
            )
        });
        let has_ordinary_role = callable_alternatives
            .iter()
            .any(|alternative| alternative.role == ScalaCallableRole::Ordinary);
        let kind = if target.is_field() {
            TargetKind::Field
        } else if target.is_synthetic()
            || owner_name.as_deref() == Some(target.identifier())
            || has_constructor_role && !has_ordinary_role
        {
            TargetKind::Constructor
        } else {
            TargetKind::Method
        };
        let is_extension_method = callable_alternatives
            .iter()
            .any(|alternative| alternative.extension_receiver_type.is_some());
        let accepts_field_implementation = kind == TargetKind::Method
            && scala
                .project_types()
                .is_abstract_scala_method(scala, target)
            && callable_alternatives.iter().any(|alternative| {
                alternative.role == ScalaCallableRole::Ordinary && alternative.shape.is_empty()
            });
        let member_name = if kind == TargetKind::Constructor {
            owner_name.clone()?
        } else {
            target.identifier().to_string()
        };
        let member_owners = inherited_member_owners(scala, &owner, kind, &member_name, arity);
        let accepts_companion_apply_syntax = kind == TargetKind::Method
            && member_name == "apply"
            && companion_apply_owner_is_unambiguous(scala, target, owner.as_ref());
        Some(Self {
            target: target.clone(),
            target_fq_name: scala_normalized_fq_name(&target.fq_name()),
            owner_fq_name: owner.as_ref().map(CodeUnit::fq_name),
            owner,
            family_owners: member_owners.family_owners,
            receiver_owners: member_owners.receiver_owners,
            owner_name,
            kind,
            member_name,
            arity,
            callable_alternatives,
            is_extension_method,
            accepts_field_implementation,
            is_object_type: false,
            accepts_apply_role: false,
            type_parent: None,
            accepts_companion_apply_syntax,
        })
    }
}

fn companion_apply_owner_is_unambiguous(
    scala: &ScalaAnalyzer,
    target: &CodeUnit,
    owner: Option<&CodeUnit>,
) -> bool {
    let Some(_owner) = owner else {
        return false;
    };
    if let Some(structural_owner) = scala.structural_parent_of(target) {
        if scala
            .project_types()
            .type_accepts_object_roles(scala, &structural_owner)
        {
            return true;
        }
        return inherited_companion_apply_fallback_is_unambiguous(scala, target, &structural_owner);
    }
    let normalized_target = scala_normalized_fq_name(&target.fq_name());
    !scala
        .global_usage_definition_index()
        .by_normalized_fqn(&normalized_target)
        .iter()
        .filter(|candidate| candidate.is_function() && *candidate != target)
        .filter_map(|candidate| scala.structural_parent_of(candidate))
        .any(|candidate_owner| {
            scala
                .project_types()
                .type_accepts_object_roles(scala, &candidate_owner)
        })
}

fn inherited_companion_apply_fallback_is_unambiguous(
    scala: &ScalaAnalyzer,
    target: &CodeUnit,
    owner: &CodeUnit,
) -> bool {
    let index = scala.global_usage_definition_index();
    let normalized_target = scala_normalized_fq_name(&target.fq_name());
    if index
        .by_normalized_fqn(&normalized_target)
        .iter()
        .any(|candidate| candidate.is_function() && candidate != target)
    {
        return false;
    }

    let normalized_owner = scala_normalized_fq_name(&owner.fq_name());
    let mut companions = index
        .by_normalized_fqn(&normalized_owner)
        .iter()
        .filter(|candidate| {
            candidate.is_class()
                && *candidate != owner
                && scala
                    .project_types()
                    .type_accepts_object_roles(scala, candidate)
        });
    let Some(companion) = companions.next() else {
        return false;
    };
    if companions.next().is_some() {
        return false;
    }

    let Some(facts) = scala.forward_owner_facts(companion) else {
        return false;
    };
    !facts.supertype_lookup_paths.is_empty()
        && std::iter::once(companion.clone())
            .chain(scala.get_ancestors(companion))
            .all(|candidate_owner| {
                !scala
                    .definitions(&format!("{}.apply", candidate_owner.fq_name()))
                    .any(|candidate| {
                        candidate.is_function()
                            && scala.structural_parent_of(&candidate).as_ref()
                                == Some(&candidate_owner)
                    })
            })
}

struct InheritedMemberOwners {
    family_owners: Vec<CodeUnit>,
    receiver_owners: Vec<CodeUnit>,
}

#[derive(Clone, PartialEq, Eq)]
enum InheritedMemberState {
    Related(HashSet<CodeUnit>),
    Blocked,
    None,
}

enum DirectMemberState {
    RelatedOverride,
    BlockingDeclaration,
    None,
}

fn inherited_member_owners(
    scala: &ScalaAnalyzer,
    owner: &Option<CodeUnit>,
    kind: TargetKind,
    member_name: &str,
    arity: Option<usize>,
) -> InheritedMemberOwners {
    let Some(owner) = owner else {
        return InheritedMemberOwners {
            family_owners: Vec::new(),
            receiver_owners: Vec::new(),
        };
    };
    let mut family_owners = vec![owner.clone()];
    let mut receiver_owners = vec![owner.clone()];
    if !matches!(kind, TargetKind::Method | TargetKind::Field) {
        return InheritedMemberOwners {
            family_owners,
            receiver_owners,
        };
    }
    let mut seen = HashSet::from_iter([owner.clone()]);
    let mut related_declaration_owners = seen.clone();
    let mut inherited_state_by_owner = HashMap::from_iter([(
        owner.clone(),
        InheritedMemberState::Related(HashSet::from_iter([owner.clone()])),
    )]);
    for descendant in scala.get_descendants(owner) {
        if !seen.insert(descendant.clone()) {
            continue;
        }
        match direct_member_state(scala, &descendant, kind, member_name, arity) {
            DirectMemberState::RelatedOverride => {
                related_declaration_owners.insert(descendant.clone());
                inherited_state_by_owner.insert(
                    descendant.clone(),
                    InheritedMemberState::Related(HashSet::from_iter([descendant.clone()])),
                );
                family_owners.push(descendant.clone());
                receiver_owners.push(descendant);
            }
            DirectMemberState::BlockingDeclaration => {
                inherited_state_by_owner.insert(descendant.clone(), InheritedMemberState::Blocked);
            }
            DirectMemberState::None => {
                let state = inherited_member_state_from_ancestors(
                    scala,
                    &descendant,
                    kind,
                    member_name,
                    arity,
                    &related_declaration_owners,
                    &inherited_state_by_owner,
                );
                let is_related = matches!(state, InheritedMemberState::Related(_));
                inherited_state_by_owner.insert(descendant.clone(), state);
                if is_related {
                    receiver_owners.push(descendant);
                }
            }
        }
    }
    InheritedMemberOwners {
        family_owners,
        receiver_owners,
    }
}

fn inherited_member_state_from_ancestors(
    scala: &ScalaAnalyzer,
    descendant: &CodeUnit,
    kind: TargetKind,
    member_name: &str,
    arity: Option<usize>,
    related_declaration_owners: &HashSet<CodeUnit>,
    inherited_state_by_owner: &HashMap<CodeUnit, InheritedMemberState>,
) -> InheritedMemberState {
    let mut related_matches = HashSet::default();
    let mut has_blocking_match = false;
    for ancestor in scala.get_direct_ancestors(descendant) {
        if owner_declares_matching_member(scala, &ancestor, kind, member_name, arity) {
            if related_declaration_owners.contains(&ancestor) {
                related_matches.insert(ancestor);
            } else {
                has_blocking_match = true;
            }
            continue;
        }

        match inherited_state_by_owner.get(&ancestor) {
            Some(InheritedMemberState::Related(declarations)) => {
                related_matches.extend(declarations.iter().cloned());
            }
            Some(InheritedMemberState::Blocked) => has_blocking_match = true,
            Some(InheritedMemberState::None) | None => {}
        }
    }
    if has_blocking_match || related_matches.len() > 1 {
        return InheritedMemberState::Blocked;
    }
    if related_matches.len() == 1 {
        InheritedMemberState::Related(related_matches)
    } else {
        InheritedMemberState::None
    }
}

fn direct_member_state(
    scala: &ScalaAnalyzer,
    owner: &CodeUnit,
    kind: TargetKind,
    member_name: &str,
    arity: Option<usize>,
) -> DirectMemberState {
    if scala
        .definitions(&format!("{}.{}$", owner.fq_name(), member_name))
        .any(|unit| {
            unit.is_class()
                && unit.short_name().ends_with('$')
                && scala.structural_parent_of(&unit).as_ref() == Some(owner)
        })
    {
        return DirectMemberState::BlockingDeclaration;
    }
    if kind == TargetKind::Method
        && scala
            .definitions(&format!("{}.{}", owner.fq_name(), member_name))
            .any(|unit| {
                unit.is_function()
                    && scala.parent_of(&unit).as_ref() == Some(owner)
                    && method_arity_matches(scala, &unit, arity)
            })
    {
        return DirectMemberState::RelatedOverride;
    }
    if owner_declares_matching_member(scala, owner, kind, member_name, arity) {
        DirectMemberState::BlockingDeclaration
    } else {
        DirectMemberState::None
    }
}

fn owner_declares_matching_member(
    scala: &ScalaAnalyzer,
    owner: &CodeUnit,
    kind: TargetKind,
    member_name: &str,
    arity: Option<usize>,
) -> bool {
    scala
        .definitions(&format!("{}.{}", owner.fq_name(), member_name))
        .any(|unit| {
            scala.parent_of(&unit).as_ref() == Some(owner)
                && member_matches_target_kind(scala, &unit, kind, arity)
        })
}

pub(super) fn member_matches_target_kind(
    scala: &ScalaAnalyzer,
    unit: &CodeUnit,
    kind: TargetKind,
    arity: Option<usize>,
) -> bool {
    match kind {
        TargetKind::Method => {
            (unit.is_function() && method_arity_matches(scala, unit, arity))
                || (unit.is_field() && arity.is_none_or(|arity| arity == 0))
        }
        TargetKind::Field => {
            unit.is_field() || (unit.is_function() && method_arity_matches(scala, unit, Some(0)))
        }
        TargetKind::Type | TargetKind::Constructor => false,
    }
}

pub(in crate::analyzer::usages) fn scala_builtin_type_name(
    type_text: &str,
) -> Option<&'static str> {
    let simple = scala_simple_type_name(type_text)?;
    match simple {
        "String" => Some("String"),
        "Int" => Some("Int"),
        "Long" => Some("Long"),
        "Double" => Some("Double"),
        "Float" => Some("Float"),
        "Boolean" => Some("Boolean"),
        "Char" => Some("Char"),
        "Byte" => Some("Byte"),
        "Short" => Some("Short"),
        "Unit" => Some("Unit"),
        _ => None,
    }
}

pub(in crate::analyzer::usages) fn scala_literal_type_name(kind: &str) -> Option<&'static str> {
    match kind {
        "string" | "string_literal" | "interpolated_string_expression" => Some("String"),
        "integer_literal" => Some("Int"),
        "floating_point_literal" => Some("Double"),
        "boolean_literal" | "true" | "false" => Some("Boolean"),
        "character_literal" => Some("Char"),
        _ => None,
    }
}

pub(in crate::analyzer::usages) fn scala_extension_receiver_matches_resolved(
    extension_receiver_type: Option<&str>,
    receiver_owner: Option<&str>,
    mut resolve_type: impl FnMut(&str) -> Option<String>,
) -> bool {
    let Some(extension_receiver_type) = extension_receiver_type else {
        return true;
    };
    let Some(receiver_owner) = receiver_owner else {
        return false;
    };
    let resolved = resolve_type(extension_receiver_type)
        .or_else(|| scala_builtin_type_name(extension_receiver_type).map(str::to_string))
        .unwrap_or_else(|| extension_receiver_type.to_string());
    scala_normalized_fq_name(&resolved) == scala_normalized_fq_name(receiver_owner)
}

pub(in crate::analyzer::usages) fn extension_receiver_type(signature: &str) -> Option<String> {
    let trimmed = signature.strip_prefix("extension ")?.trim_start();
    let parameters = trimmed.strip_prefix('(')?.split_once(')')?.0;
    let parameter = parameters.split(',').next()?.trim();
    let (_, type_text) = parameter.split_once(':')?;
    let receiver_type = type_text.trim();
    (!receiver_type.is_empty()).then(|| receiver_type.to_string())
}

pub(in crate::analyzer::usages) fn resolved_extension_receiver_type(
    scala: &ScalaAnalyzer,
    unit: &CodeUnit,
    signature: &str,
) -> Option<String> {
    extension_receiver_type(signature).map(|receiver_type| {
        scala_resolve_declared_type(scala, unit.source(), unit.package_name(), &receiver_type)
            .unwrap_or(receiver_type)
    })
}

pub(in crate::analyzer::usages) fn scala_resolve_declared_type(
    scala: &ScalaAnalyzer,
    file: &ProjectFile,
    package_name: &str,
    type_text: &str,
) -> Option<String> {
    if let Some(builtin) = scala_builtin_type_name(type_text) {
        return Some(builtin.to_string());
    }
    let base = scala_type_base(type_text)?;
    let simple = scala_simple_type_name(base)?;

    for import in scala.import_info_of(file) {
        let Some(path) = scala_import_path(&import) else {
            continue;
        };
        if import.is_wildcard {
            for package in import_candidate_fq_names(&path, package_name) {
                if let Some(fqn) = scala_declared_type_in_package(scala, &package, simple) {
                    return Some(fqn);
                }
            }
            continue;
        }

        let local_name = import
            .identifier
            .as_deref()
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path));
        if local_name != simple {
            continue;
        }
        for candidate in import_candidate_fq_names(&path, package_name) {
            if let Some(fqn) = scala_declared_type_fqn(scala, &candidate) {
                return Some(fqn);
            }
        }
    }

    if let Some(fqn) = scala_declared_type_in_package(scala, package_name, simple) {
        return Some(fqn);
    }
    if base.contains('.') {
        for candidate in import_candidate_fq_names(base, package_name) {
            if let Some(fqn) = scala_declared_type_fqn(scala, &candidate) {
                return Some(fqn);
            }
        }
    }
    scala_declared_type_fqn(scala, base)
}

fn scala_declared_type_in_package(
    scala: &ScalaAnalyzer,
    package_name: &str,
    simple: &str,
) -> Option<String> {
    preferred_scala_type(
        scala
            .global_usage_definition_index()
            .types_in_package(package_name, simple)
            .iter()
            .filter(|unit| is_package_level_type(unit)),
    )
    .map(|unit| unit.fq_name())
}

fn scala_declared_type_fqn(scala: &ScalaAnalyzer, fqn: &str) -> Option<String> {
    let normalized = scala_normalized_fq_name(fqn);
    preferred_scala_type(
        scala
            .global_usage_definition_index()
            .by_normalized_fqn(&normalized)
            .iter()
            .filter(|unit| unit.is_class()),
    )
    .map(|unit| unit.fq_name())
}

pub(in crate::analyzer::usages) fn preferred_scala_type<'a>(
    units: impl IntoIterator<Item = &'a CodeUnit>,
) -> Option<&'a CodeUnit> {
    let mut first = None;
    for unit in units {
        if first.is_none() {
            first = Some(unit);
        }
        if !unit.short_name().ends_with('$') {
            return Some(unit);
        }
    }
    first
}

fn scala_type_base(type_text: &str) -> Option<&str> {
    type_text
        .trim()
        .split(['[', '(', '{', ' ', '<'])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn scala_simple_type_name(type_text: &str) -> Option<&str> {
    type_text
        .trim()
        .split(['[', '(', '{', ' ', '<'])
        .next()
        .and_then(|base| base.rsplit('.').next())
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

pub(in crate::analyzer::usages) fn method_arity_matches(
    scala: &ScalaAnalyzer,
    unit: &CodeUnit,
    target_arity: Option<usize>,
) -> bool {
    let Some(target_arity) = target_arity else {
        return true;
    };
    method_signature_arity(scala, unit).is_none_or(|arity| arity == target_arity)
}

pub(in crate::analyzer::usages) fn method_signature_arity(
    scala: &ScalaAnalyzer,
    unit: &CodeUnit,
) -> Option<usize> {
    unit.signature().and_then(signature_arity).or_else(|| {
        scala
            .signatures(unit)
            .into_iter()
            .find_map(|signature| signature_arity(&signature))
    })
}

fn owner_of(scala: &ScalaAnalyzer, target: &CodeUnit) -> Option<CodeUnit> {
    if let Some(owner) = scala.structural_parent_of(target) {
        return owner.is_class().then_some(owner);
    }

    if let Some((owner_short, _)) = target.short_name().rsplit_once('.') {
        let owner_fq = if target.package_name().is_empty() {
            owner_short.to_string()
        } else {
            format!("{}.{}", target.package_name(), owner_short)
        };
        if let Some(owner) = scala.definitions(&owner_fq).find(|unit| unit.is_class()) {
            return Some(owner);
        }
    }

    scala
        .all_declarations()
        .filter(|unit| unit.is_class())
        .find(|candidate| {
            scala
                .direct_children(candidate)
                .into_iter()
                .any(|child| &child == target)
        })
}

pub(in crate::analyzer::usages) fn import_candidate_fq_names(
    path: &str,
    package_name: &str,
) -> HashSet<String> {
    let mut candidates = HashSet::from_iter([path.to_string()]);
    if !package_name.is_empty() && !path.starts_with(&format!("{package_name}.")) {
        candidates.insert(format!("{package_name}.{path}"));
    }
    candidates
}

pub(in crate::analyzer::usages) fn import_candidate_owner_fq_names(
    path: &str,
    package_name: &str,
) -> HashSet<String> {
    let mut owners = HashSet::default();
    for candidate in import_candidate_fq_names(path, package_name) {
        owners.insert(candidate.clone());
        if !candidate.ends_with('$') {
            owners.insert(format!("{candidate}$"));
        }
    }
    owners
}

fn signature_arity(signature: &str) -> Option<usize> {
    if let Some(extension_signature) = signature.strip_prefix("extension ") {
        let after_receiver = extension_signature.split_once(')')?.1.trim_start();
        return after_receiver
            .find('(')
            .and_then(|open| parenthesized_arity(&after_receiver[open..]))
            .or(Some(0));
    }
    let open = signature.find('(')?;
    parenthesized_arity(&signature[open..])
}

pub(in crate::analyzer::usages) fn package_name_of(
    scala: &ScalaAnalyzer,
    file: &ProjectFile,
) -> Option<String> {
    scala
        .declarations(file)
        .into_iter()
        .find(|unit| !unit.is_file_scope())
        .map(|unit| unit.package_name().to_string())
}

pub(in crate::analyzer::usages) fn scala_normalized_fq_name(fq_name: &str) -> String {
    fq_name.replace("$.", ".").trim_end_matches('$').to_string()
}

pub(in crate::analyzer::usages) fn scala_display_name(unit: &CodeUnit) -> String {
    unit.short_name()
        .rsplit('.')
        .next()
        .unwrap_or(unit.short_name())
        .trim_end_matches('$')
        .to_string()
}
