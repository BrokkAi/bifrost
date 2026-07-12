use crate::analyzer::usages::scala_graph::syntax::{parenthesized_arity, scala_import_path};
use crate::analyzer::{
    CodeUnit, DefinitionLookupIndex, IAnalyzer, ImportAnalysisProvider, ImportInfo, ProjectFile,
    ScalaAnalyzer, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};

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
    pub(super) extension_receiver_type: Option<String>,
    family_owner_fq_names: HashSet<String>,
    receiver_owner_fq_names: HashSet<String>,
    pub(super) arity: Option<usize>,
    pub(super) is_extension_method: bool,
    pub(super) unapplied_reference_is_unambiguous: bool,
}

impl TargetSpec {
    pub(super) fn from_target(scala: &ScalaAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            let owner_name = scala_display_name(target);
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner: Some(target.clone()),
                family_owners: vec![target.clone()],
                receiver_owners: vec![target.clone()],
                member_name: owner_name.clone(),
                target_fq_name: scala_normalized_fq_name(&target.fq_name()),
                owner_fq_name: Some(scala_normalized_fq_name(&target.fq_name())),
                extension_receiver_type: None,
                family_owner_fq_names: HashSet::from_iter([scala_normalized_fq_name(
                    &target.fq_name(),
                )]),
                receiver_owner_fq_names: HashSet::from_iter([scala_normalized_fq_name(
                    &target.fq_name(),
                )]),
                owner_name: Some(owner_name),
                arity: None,
                is_extension_method: false,
                unapplied_reference_is_unambiguous: false,
            });
        }

        let owner = owner_of(scala, target);
        let owner_name = owner.as_ref().map(scala_display_name);
        let kind = if target.is_field() {
            TargetKind::Field
        } else if target.is_synthetic() || owner_name.as_deref() == Some(target.identifier()) {
            TargetKind::Constructor
        } else {
            TargetKind::Method
        };
        let arity = target.signature().and_then(signature_arity).or_else(|| {
            scala
                .signatures(target)
                .into_iter()
                .find_map(|sig| signature_arity(&sig))
        });
        let signature = target
            .signature()
            .map(str::to_string)
            .or_else(|| scala.signatures(target).into_iter().next());
        let is_extension_method = signature
            .as_deref()
            .is_some_and(|signature| signature.starts_with("extension "));
        let extension_receiver_type = signature
            .as_deref()
            .and_then(|signature| resolved_extension_receiver_type(scala, target, signature));
        let member_name = if kind == TargetKind::Constructor {
            owner_name.clone()?
        } else {
            target.identifier().to_string()
        };
        let unapplied_reference_is_unambiguous = kind == TargetKind::Method
            && scala.signatures(target).len() <= 1
            && scala
                .definitions(&target.fq_name())
                .filter(CodeUnit::is_function)
                .take(2)
                .count()
                == 1;
        let member_owners = inherited_member_owners(scala, &owner, kind, &member_name, arity);
        let family_owner_fq_names = member_owners
            .family_owners
            .iter()
            .map(|owner| scala_normalized_fq_name(&owner.fq_name()))
            .collect();
        let receiver_owner_fq_names = member_owners
            .receiver_owners
            .iter()
            .map(|owner| scala_normalized_fq_name(&owner.fq_name()))
            .collect();
        Some(Self {
            target: target.clone(),
            target_fq_name: scala_normalized_fq_name(&target.fq_name()),
            owner_fq_name: owner
                .as_ref()
                .map(|owner| scala_normalized_fq_name(&owner.fq_name())),
            extension_receiver_type,
            owner,
            family_owners: member_owners.family_owners,
            receiver_owners: member_owners.receiver_owners,
            owner_name,
            kind,
            member_name,
            family_owner_fq_names,
            receiver_owner_fq_names,
            arity,
            is_extension_method,
            unapplied_reference_is_unambiguous,
        })
    }

    pub(super) fn owner_fq_matches(&self, owner_fq_name: &str) -> bool {
        self.family_owner_fq_names
            .contains(&scala_normalized_fq_name(owner_fq_name))
    }

    pub(super) fn receiver_owner_fq_matches(&self, owner_fq_name: &str) -> bool {
        let normalized = scala_normalized_fq_name(owner_fq_name);
        self.receiver_owner_fq_names.contains(&normalized)
            || scala_builtin_type_name(&normalized).is_some_and(|builtin| {
                self.receiver_owner_fq_names
                    .contains(&format!("scala.{builtin}"))
            })
    }

    pub(super) fn related_override_owner_fq_matches(&self, owner_fq_name: &str) -> bool {
        let normalized = scala_normalized_fq_name(owner_fq_name);
        self.owner_fq_name.as_deref() != Some(normalized.as_str())
            && self.family_owner_fq_names.contains(&normalized)
    }
}

struct InheritedMemberOwners {
    family_owners: Vec<CodeUnit>,
    receiver_owners: Vec<CodeUnit>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InheritedMemberState {
    Related,
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
    let mut seen = HashSet::from_iter([scala_normalized_fq_name(&owner.fq_name())]);
    let mut related_owner_fq_names = seen.clone();
    let mut inherited_state_by_owner = HashMap::from_iter([(
        scala_normalized_fq_name(&owner.fq_name()),
        InheritedMemberState::Related,
    )]);
    for descendant in scala.get_descendants(owner) {
        let descendant_fq_name = scala_normalized_fq_name(&descendant.fq_name());
        if !seen.insert(descendant_fq_name.clone()) {
            continue;
        }
        match direct_member_state(scala, &descendant, kind, member_name, arity) {
            DirectMemberState::RelatedOverride => {
                related_owner_fq_names.insert(descendant_fq_name.clone());
                inherited_state_by_owner.insert(descendant_fq_name, InheritedMemberState::Related);
                family_owners.push(descendant.clone());
                receiver_owners.push(descendant);
            }
            DirectMemberState::BlockingDeclaration => {
                inherited_state_by_owner.insert(descendant_fq_name, InheritedMemberState::Blocked);
            }
            DirectMemberState::None => {
                let state = inherited_member_state_from_ancestors(
                    scala,
                    &descendant,
                    kind,
                    member_name,
                    arity,
                    &related_owner_fq_names,
                    &inherited_state_by_owner,
                );
                inherited_state_by_owner.insert(descendant_fq_name, state);
                if state == InheritedMemberState::Related {
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
    related_owner_fq_names: &HashSet<String>,
    inherited_state_by_owner: &HashMap<String, InheritedMemberState>,
) -> InheritedMemberState {
    let mut related_matches = HashSet::default();
    let mut has_blocking_match = false;
    for ancestor in scala.get_direct_ancestors(descendant) {
        let ancestor_fq_name = scala_normalized_fq_name(&ancestor.fq_name());
        if owner_declares_matching_member(scala, &ancestor, kind, member_name, arity) {
            if related_owner_fq_names.contains(&ancestor_fq_name) {
                related_matches.insert(ancestor_fq_name);
            } else {
                has_blocking_match = true;
            }
            continue;
        }

        match inherited_state_by_owner.get(&ancestor_fq_name) {
            Some(InheritedMemberState::Related) => {
                related_matches.insert(ancestor_fq_name);
            }
            Some(InheritedMemberState::Blocked) => has_blocking_match = true,
            Some(InheritedMemberState::None) | None => {}
        }
    }
    if has_blocking_match || related_matches.len() > 1 {
        return InheritedMemberState::Blocked;
    }
    if related_matches.len() == 1 {
        InheritedMemberState::Related
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
    if kind == TargetKind::Method
        && scala
            .definitions(&format!("{}.{}", owner.fq_name(), member_name))
            .any(|unit| unit.is_function() && method_arity_matches(scala, &unit, arity))
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
        .any(|unit| member_matches_target_kind(scala, &unit, kind, arity))
}

fn member_matches_target_kind(
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

fn imported_factory_return_owner(
    scala: &ScalaAnalyzer,
    unit: &CodeUnit,
    spec: &TargetSpec,
) -> Option<String> {
    let signature = unit
        .signature()
        .map(str::to_string)
        .or_else(|| scala.signatures(unit).into_iter().next())?;
    let return_type = signature_return_type(&signature)?;
    spec.receiver_owners.iter().find_map(|owner| {
        return_type_matches_owner(return_type, unit.package_name(), owner)
            .then(|| scala_normalized_fq_name(&owner.fq_name()))
    })
}

fn return_type_matches_owner(return_type: &str, return_package: &str, owner: &CodeUnit) -> bool {
    let base = return_type_base(return_type);
    if scala_normalized_fq_name(base) == scala_normalized_fq_name(&owner.fq_name()) {
        return true;
    }
    !base.contains('.')
        && return_package == owner.package_name()
        && base == scala_display_name(owner)
}

fn signature_return_type(signature: &str) -> Option<&str> {
    let (_, after_colon) = signature.rsplit_once(':')?;
    let end = after_colon.find(['=', '{']).unwrap_or(after_colon.len());
    let return_type = after_colon[..end].trim();
    (!return_type.is_empty()).then_some(return_type)
}

fn return_type_base(return_type: &str) -> &str {
    return_type
        .split(['[', '(', '{', ' '])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(return_type)
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
    _resolve_type: impl FnMut(&str) -> Option<String>,
) -> bool {
    let Some(extension_receiver_type) = extension_receiver_type else {
        return true;
    };
    let Some(receiver_owner) = receiver_owner else {
        return false;
    };
    scala_builtin_type_name(extension_receiver_type).is_some_and(|extension_receiver| {
        scala_normalized_fq_name(extension_receiver) == scala_normalized_fq_name(receiver_owner)
    }) || scala_normalized_fq_name(extension_receiver_type)
        == scala_normalized_fq_name(receiver_owner)
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
            .definition_lookup_index()
            .types_in_package(package_name, simple),
    )
    .map(|unit| unit.fq_name())
}

fn scala_declared_type_fqn(scala: &ScalaAnalyzer, fqn: &str) -> Option<String> {
    let normalized = scala_normalized_fq_name(fqn);
    preferred_scala_type(
        scala
            .definition_lookup_index()
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

pub(super) struct Visibility {
    pub(super) type_names: HashSet<String>,
    pub(super) owner_names: HashSet<String>,
    owner_name_to_fq_name: HashMap<String, String>,
    receiver_type_name_to_fq_name: HashMap<String, String>,
    receiver_name_to_fq_name: HashMap<String, String>,
    pub(super) direct_member_names: HashSet<String>,
    pub(super) ambiguous_direct_member_names: HashSet<String>,
}

impl Visibility {
    pub(super) fn for_file(scala: &ScalaAnalyzer, file: &ProjectFile, spec: &TargetSpec) -> Self {
        let mut visibility = Self {
            type_names: HashSet::default(),
            owner_names: HashSet::default(),
            owner_name_to_fq_name: HashMap::default(),
            receiver_type_name_to_fq_name: HashMap::default(),
            receiver_name_to_fq_name: HashMap::default(),
            direct_member_names: HashSet::default(),
            ambiguous_direct_member_names: ambiguous_wildcard_members(scala, file, spec),
        };

        let file_package = package_name_of(scala, file);
        if file == spec.target.source()
            || file_package.as_deref() == Some(spec.target.package_name())
        {
            visibility.type_names.insert(spec.member_name.clone());
            if spec.owner.is_none() {
                visibility
                    .direct_member_names
                    .insert(spec.member_name.clone());
            }
            if let Some(owner_name) = spec.owner_name.as_ref()
                && let Some(owner_fq_name) = spec.owner_fq_name.as_ref()
            {
                visibility.add_owner_name(owner_name.clone(), owner_fq_name.clone());
            }
        }
        if spec
            .owner
            .as_ref()
            .is_some_and(|owner| file_package.as_deref() == Some(owner.package_name()))
            && let Some(owner_name) = spec.owner_name.as_ref()
            && let Some(owner_fq_name) = spec.owner_fq_name.as_ref()
        {
            visibility.add_owner_name(owner_name.clone(), owner_fq_name.clone());
        }

        for owner in &spec.family_owners {
            if file == owner.source() || file_package.as_deref() == Some(owner.package_name()) {
                visibility.add_owner_name(
                    scala_display_name(owner),
                    scala_normalized_fq_name(&owner.fq_name()),
                );
            }
        }
        for owner in &spec.receiver_owners {
            if file == owner.source() || file_package.as_deref() == Some(owner.package_name()) {
                visibility.add_receiver_type_name(
                    scala_display_name(owner),
                    scala_normalized_fq_name(&owner.fq_name()),
                );
            }
        }

        let file_package = file_package.unwrap_or_default();
        for import in scala.import_info_of(file) {
            visibility.apply_import(scala, &import, spec, &file_package);
        }

        visibility
    }

    pub(super) fn owner_fq_name_for(&self, owner_name: &str) -> Option<&str> {
        self.owner_name_to_fq_name
            .get(owner_name)
            .map(String::as_str)
    }

    pub(super) fn receiver_type_fq_name_for(&self, owner_name: &str) -> Option<&str> {
        self.receiver_type_name_to_fq_name
            .get(owner_name)
            .map(String::as_str)
    }

    pub(super) fn receiver_fq_name_for(&self, receiver_name: &str) -> Option<&str> {
        self.receiver_name_to_fq_name
            .get(receiver_name)
            .map(String::as_str)
    }

    fn add_owner_name(&mut self, owner_name: String, owner_fq_name: String) {
        self.owner_names.insert(owner_name.clone());
        self.owner_name_to_fq_name
            .insert(owner_name, scala_normalized_fq_name(&owner_fq_name));
    }

    fn add_receiver_type_name(&mut self, owner_name: String, owner_fq_name: String) {
        self.receiver_type_name_to_fq_name
            .insert(owner_name, scala_normalized_fq_name(&owner_fq_name));
    }

    fn add_receiver_name(&mut self, receiver_name: String, owner_fq_name: String) {
        self.receiver_name_to_fq_name
            .insert(receiver_name, scala_normalized_fq_name(&owner_fq_name));
    }

    fn apply_import(
        &mut self,
        scala: &ScalaAnalyzer,
        import: &ImportInfo,
        spec: &TargetSpec,
        file_package: &str,
    ) {
        let names = Self::matching_import_names(import, spec, file_package);
        self.type_names.extend(names.type_names);
        for (owner_name, owner_fq_name) in names.owner_names {
            self.add_owner_name(owner_name, owner_fq_name);
        }
        self.direct_member_names.extend(names.direct_member_names);
        self.apply_family_owner_import(import, spec, file_package);
        self.apply_receiver_owner_import(import, spec, file_package);
        self.apply_imported_factory_receiver(scala, import, spec, file_package);
    }

    fn apply_family_owner_import(
        &mut self,
        import: &ImportInfo,
        spec: &TargetSpec,
        file_package: &str,
    ) {
        let Some(path) = scala_import_path(import) else {
            return;
        };
        if import.is_wildcard {
            let candidates = import_candidate_fq_names(&path, file_package);
            for owner in &spec.family_owners {
                if candidates.contains(owner.package_name()) {
                    self.add_owner_name(
                        scala_display_name(owner),
                        scala_normalized_fq_name(&owner.fq_name()),
                    );
                }
            }
            return;
        }
        let normalized = scala_normalized_fq_name(&path);
        for owner in &spec.family_owners {
            let owner_fq_name = scala_normalized_fq_name(&owner.fq_name());
            if normalized == owner_fq_name {
                let local_name = import
                    .identifier
                    .clone()
                    .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path).to_string());
                self.add_owner_name(local_name, owner_fq_name);
            }
        }
    }

    fn apply_receiver_owner_import(
        &mut self,
        import: &ImportInfo,
        spec: &TargetSpec,
        file_package: &str,
    ) {
        let Some(path) = scala_import_path(import) else {
            return;
        };
        if import.is_wildcard {
            let candidates = import_candidate_fq_names(&path, file_package);
            for owner in &spec.receiver_owners {
                if candidates.contains(owner.package_name()) {
                    self.add_receiver_type_name(
                        scala_display_name(owner),
                        scala_normalized_fq_name(&owner.fq_name()),
                    );
                }
            }
            return;
        }
        let normalized = scala_normalized_fq_name(&path);
        for owner in &spec.receiver_owners {
            let owner_fq_name = scala_normalized_fq_name(&owner.fq_name());
            if normalized == owner_fq_name {
                let local_name = import
                    .identifier
                    .clone()
                    .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path).to_string());
                self.add_receiver_type_name(local_name, owner_fq_name);
            }
        }
    }

    fn apply_imported_factory_receiver(
        &mut self,
        scala: &ScalaAnalyzer,
        import: &ImportInfo,
        spec: &TargetSpec,
        file_package: &str,
    ) {
        if import.is_wildcard || spec.kind != TargetKind::Method {
            return;
        }
        let Some(path) = scala_import_path(import) else {
            return;
        };
        let candidate_fq_names = import_candidate_fq_names(&path, file_package);
        let local_name = import
            .identifier
            .clone()
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path).to_string());
        for candidate in candidate_fq_names {
            for unit in scala
                .definitions(&candidate)
                .filter(|unit| unit.is_function())
            {
                if let Some(owner_fq_name) = imported_factory_return_owner(scala, &unit, spec) {
                    self.add_receiver_name(local_name, owner_fq_name);
                    return;
                }
            }
            let object_candidate = object_member_fq_name(&candidate);
            for unit in scala
                .definitions(&object_candidate)
                .filter(|unit| unit.is_function())
            {
                if let Some(owner_fq_name) = imported_factory_return_owner(scala, &unit, spec) {
                    self.add_receiver_name(local_name, owner_fq_name);
                    return;
                }
            }
        }
    }

    pub(super) fn matching_import_names(
        import: &ImportInfo,
        spec: &TargetSpec,
        file_package: &str,
    ) -> ImportNames {
        let Some(path) = scala_import_path(import) else {
            return ImportNames::default();
        };
        let mut names = ImportNames::default();
        let local_name = import
            .identifier
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()).to_string());
        if import.is_wildcard {
            let candidates = import_candidate_fq_names(&path, file_package);
            let normalized_candidates: HashSet<String> = candidates
                .iter()
                .map(|candidate| scala_normalized_fq_name(candidate))
                .collect();
            if candidates.contains(spec.target.package_name()) {
                names.type_names.insert(spec.member_name.clone());
                if spec.owner.is_none() {
                    names.direct_member_names.insert(spec.member_name.clone());
                }
            }
            if spec
                .owner
                .as_ref()
                .is_some_and(|owner| candidates.contains(owner.package_name()))
                && let Some(owner_name) = spec.owner_name.as_ref()
                && let Some(owner_fq_name) = spec.owner_fq_name.as_ref()
            {
                names
                    .owner_names
                    .insert(owner_name.clone(), owner_fq_name.clone());
            }
            if spec
                .owner_fq_name
                .as_ref()
                .is_some_and(|owner_fq| normalized_candidates.contains(owner_fq))
            {
                names.direct_member_names.insert(spec.member_name.clone());
            }
            return names;
        }

        let normalized_candidates: HashSet<String> = import_candidate_fq_names(&path, file_package)
            .into_iter()
            .map(|candidate| scala_normalized_fq_name(&candidate))
            .collect();
        if normalized_candidates.contains(&spec.target_fq_name) {
            names.type_names.insert(local_name.clone());
        }
        if spec
            .owner_fq_name
            .as_ref()
            .is_some_and(|owner_fq| normalized_candidates.contains(owner_fq))
        {
            if let Some(owner_fq_name) = spec.owner_fq_name.as_ref() {
                names
                    .owner_names
                    .insert(local_name.clone(), owner_fq_name.clone());
            }
            if spec.kind == TargetKind::Constructor {
                names.type_names.insert(local_name.clone());
            }
        }
        if normalized_candidates.contains(&spec.target_fq_name) && spec.kind != TargetKind::Type {
            names.direct_member_names.insert(local_name);
        }
        names
    }
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

pub(in crate::analyzer::usages) fn scala_visible_type_fqn_from_index(
    scala: &ScalaAnalyzer,
    index: &DefinitionLookupIndex,
    file: &ProjectFile,
    name: &str,
) -> Option<String> {
    let file_package = package_name_of(scala, file).unwrap_or_default();
    let mut visible = scala_type_in_index_package(index, &file_package, name);

    for import in scala.import_info_of(file) {
        let Some(path) = scala_import_path(&import) else {
            continue;
        };
        if import.is_wildcard {
            let wildcard = scala_wildcard_type_fqn_from_index(index, &path, &file_package, name)?;
            if let Some(fqn) = wildcard {
                visible = Some(fqn);
            }
            continue;
        }

        let local_name = import
            .identifier
            .as_deref()
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()));
        if local_name != name {
            continue;
        }
        visible = Some(scala_unique_type_fqn_for_index_path(
            index,
            &path,
            &file_package,
        )?);
    }

    visible
}

fn scala_type_in_index_package(
    index: &DefinitionLookupIndex,
    package: &str,
    name: &str,
) -> Option<String> {
    preferred_scala_type(index.types_in_package(package, name)).map(|unit| unit.fq_name())
}

fn scala_wildcard_type_fqn_from_index(
    index: &DefinitionLookupIndex,
    path: &str,
    file_package: &str,
    name: &str,
) -> Option<Option<String>> {
    let mut candidates = Vec::new();
    for package in import_candidate_fq_names(path, file_package) {
        if let Some(fqn) = scala_type_in_index_package(index, &package, name) {
            candidates.push(fqn);
        }
    }
    candidates.sort();
    candidates.dedup();
    match candidates.len() {
        0 => Some(None),
        1 => candidates.pop().map(Some),
        _ => None,
    }
}

fn scala_unique_type_fqn_for_index_path(
    index: &DefinitionLookupIndex,
    path: &str,
    file_package: &str,
) -> Option<String> {
    let mut candidates = Vec::new();
    for candidate in import_candidate_fq_names(path, file_package) {
        let normalized = scala_normalized_fq_name(&candidate);
        if let Some(unit) = preferred_scala_type(
            index
                .by_normalized_fqn(&normalized)
                .iter()
                .filter(|unit| unit.is_class()),
        ) {
            candidates.push(unit.fq_name());
        }
    }
    candidates.sort();
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn object_member_fq_name(fq_name: &str) -> String {
    let Some((owner, member)) = fq_name.rsplit_once('.') else {
        return fq_name.to_string();
    };
    if owner.ends_with('$') {
        fq_name.to_string()
    } else {
        format!("{owner}$.{member}")
    }
}

#[derive(Default)]
pub(super) struct ImportNames {
    pub(super) type_names: HashSet<String>,
    pub(super) owner_names: HashMap<String, String>,
    pub(super) direct_member_names: HashSet<String>,
}

fn ambiguous_wildcard_members(
    scala: &ScalaAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
) -> HashSet<String> {
    if spec.kind == TargetKind::Type {
        return HashSet::default();
    }

    let mut exposing_wildcards = HashSet::default();
    let file_package = package_name_of(scala, file).unwrap_or_default();
    for import in scala.import_info_of(file) {
        if !import.is_wildcard {
            continue;
        }
        let Some(path) = scala_import_path(&import) else {
            continue;
        };
        if wildcard_path_could_expose(scala, &path, &file_package, spec) {
            exposing_wildcards.insert(path);
        }
    }

    let mut ambiguous = HashSet::default();
    if exposing_wildcards.len() > 1 {
        ambiguous.insert(spec.member_name.clone());
    }
    ambiguous
}

fn wildcard_path_could_expose(
    scala: &ScalaAnalyzer,
    path: &str,
    file_package: &str,
    spec: &TargetSpec,
) -> bool {
    let candidates = import_candidate_fq_names(path, file_package);
    let normalized_candidates: HashSet<String> = candidates
        .iter()
        .map(|candidate| scala_normalized_fq_name(candidate))
        .collect();
    if spec.is_extension_method {
        return scala.all_declarations().any(|unit| {
            unit.is_function()
                && unit.identifier() == spec.member_name
                && unit
                    .signature()
                    .map(str::to_string)
                    .or_else(|| scala.signatures(&unit).into_iter().next())
                    .is_some_and(|signature| signature.starts_with("extension "))
                && owner_of(scala, &unit).is_some_and(|owner| {
                    normalized_candidates.contains(&scala_normalized_fq_name(&owner.fq_name()))
                })
        });
    }

    if spec.owner.is_none() {
        return candidates.iter().any(|candidate| {
            scala
                .definitions(&format!("{candidate}.{}", spec.member_name))
                .any(|unit| {
                    matches!(spec.kind, TargetKind::Method) && unit.is_function()
                        || matches!(spec.kind, TargetKind::Field) && unit.is_field()
                })
        });
    }

    spec.owner_fq_name
        .as_ref()
        .is_some_and(|owner_fq| normalized_candidates.contains(owner_fq))
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
