use crate::analyzer::{CodeUnit, DefinitionLookupIndex};

pub(crate) trait FileImportContext {
    fn imported_type_names(&self, simple: &str) -> Vec<String>;

    fn package_of_file(&self) -> &str;

    fn select_unique<'a>(&self, candidates: Vec<&'a CodeUnit>) -> Option<&'a CodeUnit> {
        (candidates.len() == 1).then(|| candidates[0])
    }
}

pub(crate) fn resolve_visible_type<'a>(
    index: &'a DefinitionLookupIndex,
    ctx: &dyn FileImportContext,
    raw_name: &str,
    normalize: &dyn Fn(&str) -> String,
    visible: &dyn Fn(&CodeUnit) -> bool,
) -> Option<&'a CodeUnit> {
    let name = raw_name.trim();
    if name.is_empty() {
        return None;
    }

    if name.contains('.')
        && let Some(unit) =
            ctx.select_unique(type_candidates_by_fqn(index, name, normalize, visible))
    {
        return Some(unit);
    }

    let mut imported = Vec::new();
    for imported_name in ctx.imported_type_names(name) {
        imported.extend(type_candidates_by_fqn(
            index,
            &imported_name,
            normalize,
            visible,
        ));
    }
    if let Some(unit) = ctx.select_unique(dedup_candidates(imported)) {
        return Some(unit);
    }

    let package = ctx.package_of_file();
    if !package.is_empty() {
        let same_package = format!("{package}.{name}");
        if let Some(unit) = ctx.select_unique(type_candidates_by_fqn(
            index,
            &same_package,
            normalize,
            visible,
        )) {
            return Some(unit);
        }
    }

    ctx.select_unique(type_candidates_by_fqn(index, name, normalize, visible))
}

fn type_candidates_by_fqn<'a>(
    index: &'a DefinitionLookupIndex,
    name: &str,
    normalize: &dyn Fn(&str) -> String,
    visible: &dyn Fn(&CodeUnit) -> bool,
) -> Vec<&'a CodeUnit> {
    let mut candidates = index
        .by_fqn(name)
        .iter()
        .filter(|unit| unit.is_class() && visible(unit))
        .collect::<Vec<_>>();
    let normalized = normalize(name);
    if normalized != name {
        candidates.extend(
            index
                .by_normalized_fqn(&normalized)
                .iter()
                .filter(|unit| unit.is_class() && visible(unit)),
        );
    }
    dedup_candidates(candidates)
}

fn dedup_candidates(candidates: Vec<&CodeUnit>) -> Vec<&CodeUnit> {
    let mut deduped = Vec::new();
    for candidate in candidates {
        if !deduped.contains(&candidate) {
            deduped.push(candidate);
        }
    }
    deduped
}
