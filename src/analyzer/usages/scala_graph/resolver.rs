use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, Language,
    MultiAnalyzer, ProjectFile, ScalaAnalyzer,
};
use crate::hash::HashSet;

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
    pub(super) member_name: String,
    pub(super) target_fq_name: String,
    pub(super) owner_fq_name: Option<String>,
    pub(super) arity: Option<usize>,
}

impl TargetSpec {
    pub(super) fn from_target(scala: &ScalaAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            let owner_name = scala_display_name(target);
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner: Some(target.clone()),
                member_name: owner_name.clone(),
                target_fq_name: scala_normalized_fq_name(&target.fq_name()),
                owner_fq_name: Some(scala_normalized_fq_name(&target.fq_name())),
                owner_name: Some(owner_name),
                arity: None,
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
        let member_name = if kind == TargetKind::Constructor {
            owner_name.clone()?
        } else {
            target.identifier().to_string()
        };
        Some(Self {
            target: target.clone(),
            target_fq_name: scala_normalized_fq_name(&target.fq_name()),
            owner_fq_name: owner
                .as_ref()
                .map(|owner| scala_normalized_fq_name(&owner.fq_name())),
            owner,
            owner_name,
            kind,
            member_name,
            arity,
        })
    }
}

pub(super) fn resolve_scala_analyzer(analyzer: &dyn IAnalyzer) -> Option<&ScalaAnalyzer> {
    if let Some(scala) = (analyzer as &dyn std::any::Any).downcast_ref::<ScalaAnalyzer>() {
        return Some(scala);
    }

    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Scala) {
        Some(AnalyzerDelegate::Scala(scala)) => Some(scala),
        _ => None,
    }
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
    pub(super) direct_member_names: HashSet<String>,
    pub(super) ambiguous_direct_member_names: HashSet<String>,
}

impl Visibility {
    pub(super) fn for_file(scala: &ScalaAnalyzer, file: &ProjectFile, spec: &TargetSpec) -> Self {
        let mut visibility = Self {
            type_names: HashSet::default(),
            owner_names: HashSet::default(),
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
            if let Some(owner_name) = spec.owner_name.as_ref() {
                visibility.owner_names.insert(owner_name.clone());
            }
        }
        if spec
            .owner
            .as_ref()
            .is_some_and(|owner| file_package.as_deref() == Some(owner.package_name()))
            && let Some(owner_name) = spec.owner_name.as_ref()
        {
            visibility.owner_names.insert(owner_name.clone());
        }

        for import in scala.import_info_of(file) {
            visibility.apply_import(import, spec);
        }

        visibility
    }

    fn apply_import(&mut self, import: &ImportInfo, spec: &TargetSpec) {
        let Some(path) = scala_import_path(import) else {
            return;
        };
        let local_name = import
            .identifier
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()).to_string());
        if import.is_wildcard {
            if path == spec.target.package_name() {
                self.type_names.insert(spec.member_name.clone());
                if spec.owner.is_none() {
                    self.direct_member_names.insert(spec.member_name.clone());
                }
            }
            if spec
                .owner
                .as_ref()
                .is_some_and(|owner| path == owner.package_name())
                && let Some(owner_name) = spec.owner_name.as_ref()
            {
                self.owner_names.insert(owner_name.clone());
            }
            if spec
                .owner_fq_name
                .as_ref()
                .is_some_and(|owner_fq| path == *owner_fq)
            {
                self.direct_member_names.insert(spec.member_name.clone());
            }
            return;
        }

        let normalized = scala_normalized_fq_name(&path);
        if normalized == spec.target_fq_name {
            self.type_names.insert(local_name.clone());
        }
        if spec
            .owner_fq_name
            .as_ref()
            .is_some_and(|owner_fq| normalized == *owner_fq)
        {
            self.owner_names.insert(local_name.clone());
            if spec.kind == TargetKind::Constructor {
                self.type_names.insert(local_name.clone());
            }
        }
        if normalized == spec.target_fq_name && spec.kind != TargetKind::Type {
            self.direct_member_names.insert(local_name);
        }
    }
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

fn balanced_parenthesized_prefix(source: &str) -> Option<&str> {
    let mut chars = source.char_indices();
    let (_, first) = chars.next()?;
    if first != '(' {
        return None;
    }
    let mut depth = 1usize;
    for (idx, ch) in chars {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(&source[1..idx]);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_commas(value: &str) -> impl Iterator<Item = &str> {
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut parts = Vec::new();
    for (idx, ch) in value.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(value[start..idx].trim());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(value[start..].trim());
    parts.into_iter().filter(|part| !part.is_empty())
}

fn signature_arity(signature: &str) -> Option<usize> {
    let open = signature.find('(')?;
    let inner = balanced_parenthesized_prefix(&signature[open..])?;
    if inner.trim().is_empty() {
        return Some(0);
    }
    Some(split_top_level_commas(inner).count())
}

fn package_name_of(scala: &ScalaAnalyzer, file: &ProjectFile) -> Option<String> {
    scala
        .declarations(file)
        .next()
        .map(|unit| unit.package_name().to_string())
}

fn scala_import_path(info: &ImportInfo) -> Option<String> {
    let trimmed = info
        .raw_snippet
        .trim()
        .strip_prefix("import ")
        .unwrap_or(info.raw_snippet.trim())
        .trim();
    if trimmed.is_empty() {
        return None;
    }
    if info.is_wildcard {
        return Some(trimmed.trim_end_matches(".*").to_string());
    }
    Some(
        trimmed
            .split_once(" as ")
            .map(|(path, _)| path)
            .unwrap_or(trimmed)
            .trim()
            .to_string(),
    )
}

fn scala_normalized_fq_name(fq_name: &str) -> String {
    fq_name.replace("$.", ".").trim_end_matches('$').to_string()
}

fn scala_display_name(unit: &CodeUnit) -> String {
    unit.short_name()
        .rsplit('.')
        .next()
        .unwrap_or(unit.short_name())
        .trim_end_matches('$')
        .to_string()
}
