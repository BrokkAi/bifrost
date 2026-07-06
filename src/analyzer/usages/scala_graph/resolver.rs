use crate::analyzer::usages::scala_graph::syntax::{parenthesized_arity, scala_import_path};
use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, ProjectFile, ScalaAnalyzer,
    TypeHierarchyProvider,
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
    pub(super) member_name: String,
    pub(super) target_fq_name: String,
    pub(super) owner_fq_name: Option<String>,
    family_owner_fq_names: HashSet<String>,
    pub(super) arity: Option<usize>,
    pub(super) is_extension_method: bool,
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
                member_name: owner_name.clone(),
                target_fq_name: scala_normalized_fq_name(&target.fq_name()),
                owner_fq_name: Some(scala_normalized_fq_name(&target.fq_name())),
                family_owner_fq_names: HashSet::from_iter([scala_normalized_fq_name(
                    &target.fq_name(),
                )]),
                owner_name: Some(owner_name),
                arity: None,
                is_extension_method: false,
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
                .first()
                .and_then(|sig| signature_arity(sig))
        });
        let is_extension_method = target
            .signature()
            .or_else(|| scala.signatures(target).first().map(String::as_str))
            .is_some_and(|signature| signature.starts_with("extension "));
        let member_name = if kind == TargetKind::Constructor {
            owner_name.clone()?
        } else {
            target.identifier().to_string()
        };
        let family_owners = method_family_owners(scala, &owner, kind, &member_name, arity);
        let family_owner_fq_names = family_owners
            .iter()
            .map(|owner| scala_normalized_fq_name(&owner.fq_name()))
            .collect();
        Some(Self {
            target: target.clone(),
            target_fq_name: scala_normalized_fq_name(&target.fq_name()),
            owner_fq_name: owner
                .as_ref()
                .map(|owner| scala_normalized_fq_name(&owner.fq_name())),
            owner,
            family_owners,
            owner_name,
            kind,
            member_name,
            family_owner_fq_names,
            arity,
            is_extension_method,
        })
    }

    pub(super) fn owner_fq_matches(&self, owner_fq_name: &str) -> bool {
        self.family_owner_fq_names
            .contains(&scala_normalized_fq_name(owner_fq_name))
    }

    pub(super) fn related_override_owner_fq_matches(&self, owner_fq_name: &str) -> bool {
        let normalized = scala_normalized_fq_name(owner_fq_name);
        self.owner_fq_name.as_deref() != Some(normalized.as_str())
            && self.family_owner_fq_names.contains(&normalized)
    }
}

fn method_family_owners(
    scala: &ScalaAnalyzer,
    owner: &Option<CodeUnit>,
    kind: TargetKind,
    member_name: &str,
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    let Some(owner) = owner else {
        return Vec::new();
    };
    let mut owners = vec![owner.clone()];
    if kind != TargetKind::Method || !scala.is_scala_trait_declaration(owner) {
        return owners;
    }
    let mut seen = HashSet::from_iter([scala_normalized_fq_name(&owner.fq_name())]);
    for descendant in scala.get_descendants(owner) {
        if !seen.insert(scala_normalized_fq_name(&descendant.fq_name())) {
            continue;
        }
        if owner_defines_compatible_method(scala, &descendant, member_name, arity) {
            owners.push(descendant);
        }
    }
    owners
}

fn owner_defines_compatible_method(
    scala: &ScalaAnalyzer,
    owner: &CodeUnit,
    member_name: &str,
    arity: Option<usize>,
) -> bool {
    scala
        .definitions(&format!("{}.{}", owner.fq_name(), member_name))
        .any(|unit| unit.is_function() && method_arity_matches(scala, unit, arity))
}

fn imported_factory_return_owner(
    scala: &ScalaAnalyzer,
    unit: &CodeUnit,
    spec: &TargetSpec,
) -> Option<String> {
    let signature = unit
        .signature()
        .or_else(|| scala.signatures(unit).first().map(String::as_str))?;
    let return_type = signature_return_type(signature)?;
    spec.family_owners.iter().find_map(|owner| {
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

pub(super) fn method_arity_matches(
    scala: &ScalaAnalyzer,
    unit: &CodeUnit,
    target_arity: Option<usize>,
) -> bool {
    let Some(target_arity) = target_arity else {
        return true;
    };
    unit.signature()
        .or_else(|| scala.signatures(unit).first().map(String::as_str))
        .and_then(signature_arity)
        .is_none_or(|arity| arity == target_arity)
}

fn owner_of(scala: &ScalaAnalyzer, target: &CodeUnit) -> Option<CodeUnit> {
    if let Some((owner_short, _)) = target.short_name().rsplit_once('.') {
        let owner_fq = if target.package_name().is_empty() {
            owner_short.to_string()
        } else {
            format!("{}.{}", target.package_name(), owner_short)
        };
        if let Some(owner) = scala
            .definitions(&owner_fq)
            .find(|unit| unit.is_class())
            .cloned()
        {
            return Some(owner);
        }
    }

    scala
        .all_declarations()
        .filter(|unit| unit.is_class())
        .find(|candidate| {
            scala
                .direct_children(candidate)
                .any(|child| child == target)
        })
        .cloned()
}

pub(super) struct Visibility {
    pub(super) type_names: HashSet<String>,
    pub(super) owner_names: HashSet<String>,
    owner_name_to_fq_name: HashMap<String, String>,
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

        let file_package = file_package.unwrap_or_default();
        for import in scala.import_info_of(file) {
            visibility.apply_import(scala, import, spec, &file_package);
        }

        visibility
    }

    pub(super) fn owner_fq_name_for(&self, owner_name: &str) -> Option<&str> {
        self.owner_name_to_fq_name
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
        self.apply_family_owner_import(import, spec);
        self.apply_imported_factory_receiver(scala, import, spec, file_package);
    }

    fn apply_family_owner_import(&mut self, import: &ImportInfo, spec: &TargetSpec) {
        let Some(path) = scala_import_path(import) else {
            return;
        };
        if import.is_wildcard {
            for owner in &spec.family_owners {
                if path == owner.package_name() {
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
                if let Some(owner_fq_name) = imported_factory_return_owner(scala, unit, spec) {
                    self.add_receiver_name(local_name, owner_fq_name);
                    return;
                }
            }
            let object_candidate = object_member_fq_name(&candidate);
            for unit in scala
                .definitions(&object_candidate)
                .filter(|unit| unit.is_function())
            {
                if let Some(owner_fq_name) = imported_factory_return_owner(scala, unit, spec) {
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
            if path == spec.target.package_name() {
                names.type_names.insert(spec.member_name.clone());
                if spec.owner.is_none() {
                    names.direct_member_names.insert(spec.member_name.clone());
                }
            }
            if spec
                .owner
                .as_ref()
                .is_some_and(|owner| path == owner.package_name())
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
                .is_some_and(|owner_fq| path == *owner_fq)
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

fn import_candidate_fq_names(path: &str, package_name: &str) -> HashSet<String> {
    let mut candidates = HashSet::from_iter([path.to_string()]);
    if !package_name.is_empty() && !path.starts_with(&format!("{package_name}.")) {
        candidates.insert(format!("{package_name}.{path}"));
    }
    candidates
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
    for import in scala.import_info_of(file) {
        if !import.is_wildcard {
            continue;
        }
        let Some(path) = scala_import_path(import) else {
            continue;
        };
        if wildcard_path_could_expose(scala, &path, spec) {
            exposing_wildcards.insert(path);
        }
    }

    let mut ambiguous = HashSet::default();
    if exposing_wildcards.len() > 1 {
        ambiguous.insert(spec.member_name.clone());
    }
    ambiguous
}

fn wildcard_path_could_expose(scala: &ScalaAnalyzer, path: &str, spec: &TargetSpec) -> bool {
    if spec.is_extension_method {
        return scala.all_declarations().any(|unit| {
            unit.is_function()
                && unit.identifier() == spec.member_name
                && unit
                    .signature()
                    .or_else(|| scala.signatures(unit).first().map(String::as_str))
                    .is_some_and(|signature| signature.starts_with("extension "))
                && owner_of(scala, unit).is_some_and(|owner| {
                    scala_normalized_fq_name(&owner.fq_name()) == scala_normalized_fq_name(path)
                })
        });
    }

    if spec.owner.is_none() {
        return scala
            .definitions(&format!("{path}.{}", spec.member_name))
            .any(|unit| {
                matches!(spec.kind, TargetKind::Method) && unit.is_function()
                    || matches!(spec.kind, TargetKind::Field) && unit.is_field()
            });
    }

    spec.owner_fq_name
        .as_ref()
        .is_some_and(|owner_fq| path == owner_fq)
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
