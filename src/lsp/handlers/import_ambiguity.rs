use crate::analyzer::{
    CSharpAnalyzer, CodeUnit, CodeUnitType, IAnalyzer, ImportAnalysisProvider, JavaAnalyzer,
    Language, ProjectFile, ScalaAnalyzer, resolve_analyzer,
};

pub(super) fn is_ambiguous_imported_reference(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    identifier: &str,
) -> bool {
    if identifier.is_empty() || identifier.contains('.') {
        return false;
    }

    match crate::analyzer::common::language_for_file(file) {
        Language::Java => resolve_analyzer::<JavaAnalyzer>(analyzer)
            .is_some_and(|java| java_wildcard_import_is_ambiguous(java, file, identifier)),
        Language::CSharp => resolve_analyzer::<CSharpAnalyzer>(analyzer)
            .is_some_and(|csharp| csharp_using_import_is_ambiguous(csharp, file, identifier)),
        Language::Scala => resolve_analyzer::<ScalaAnalyzer>(analyzer)
            .is_some_and(|scala| scala_wildcard_import_is_ambiguous(scala, file, identifier)),
        // PHP use-imports are explicit aliases; the current analyzer surface has
        // no wildcard import form to disambiguate at the LSP boundary.
        _ => false,
    }
}

fn java_wildcard_import_is_ambiguous(
    analyzer: &JavaAnalyzer,
    file: &ProjectFile,
    identifier: &str,
) -> bool {
    let imports = analyzer.import_info_of(file);
    if imports
        .iter()
        .any(|import| !import.is_wildcard && import.identifier.as_deref() == Some(identifier))
    {
        return false;
    }
    if package_local_class_exists(analyzer, file, identifier) {
        return false;
    }

    let mut candidates = Vec::new();
    for import in imports.iter().filter(|import| import.is_wildcard) {
        let Some(package) = wildcard_import_package(&import.raw_snippet) else {
            continue;
        };
        candidates.extend(
            analyzer
                .definitions(&format!("{package}.{identifier}"))
                .filter(|code_unit| code_unit.is_class()),
        );
    }
    has_multiple_distinct_candidates(candidates)
}

fn csharp_using_import_is_ambiguous(
    analyzer: &CSharpAnalyzer,
    file: &ProjectFile,
    identifier: &str,
) -> bool {
    let imports = analyzer.import_info_of(file);
    if imports
        .iter()
        .any(|import| csharp_alias_identifier(&import.raw_snippet).as_deref() == Some(identifier))
    {
        return false;
    }

    let file_namespace = analyzer.namespace_of_file(file);
    if analyzer
        .all_declarations()
        .any(|unit| is_class_named_in_package(&unit, identifier, &file_namespace))
    {
        return false;
    }

    let mut candidates = Vec::new();
    for namespace in analyzer.using_namespaces_of(file) {
        candidates.extend(
            analyzer
                .definitions(&format!("{namespace}.{identifier}"))
                .filter(|code_unit| code_unit.is_class()),
        );
    }
    has_multiple_distinct_candidates(candidates)
}

fn scala_wildcard_import_is_ambiguous(
    analyzer: &ScalaAnalyzer,
    file: &ProjectFile,
    identifier: &str,
) -> bool {
    let imports = analyzer.import_info_of(file);
    if imports
        .iter()
        .any(|import| !import.is_wildcard && import.identifier.as_deref() == Some(identifier))
    {
        return false;
    }
    if package_local_class_exists(analyzer, file, identifier) {
        return false;
    }

    let mut candidates = Vec::new();
    for import in imports.iter().filter(|import| import.is_wildcard) {
        let Some(package) = wildcard_import_package(&import.raw_snippet) else {
            continue;
        };
        candidates.extend(
            analyzer
                .definitions(&format!("{package}.{identifier}"))
                .filter(|code_unit| code_unit.is_class()),
        );
    }
    has_multiple_distinct_candidates(candidates)
}

fn package_local_class_exists(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    identifier: &str,
) -> bool {
    let Some(package) = analyzer
        .top_level_declarations(file)
        .into_iter()
        .next()
        .map(|unit| unit.package_name().to_string())
    else {
        return false;
    };
    let lookup_name = if package.is_empty() {
        identifier.to_string()
    } else {
        format!("{package}.{identifier}")
    };
    analyzer
        .definitions(&lookup_name)
        .any(|unit| unit.is_class())
}

fn is_class_named_in_package(unit: &CodeUnit, identifier: &str, package: &str) -> bool {
    unit.kind() == CodeUnitType::Class
        && unit.identifier() == identifier
        && unit.package_name() == package
}

fn has_multiple_distinct_candidates(candidates: Vec<CodeUnit>) -> bool {
    let mut iter = candidates.into_iter();
    let Some(first) = iter.next() else {
        return false;
    };
    iter.any(|candidate| candidate != first)
}

fn wildcard_import_package(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .strip_prefix("import ")
        .unwrap_or(raw.trim())
        .trim()
        .trim_end_matches(';')
        .trim();
    trimmed
        .strip_suffix(".*")
        .or_else(|| trimmed.strip_suffix("._"))
        .map(str::trim)
        .filter(|package| !package.is_empty())
        .map(str::to_string)
}

fn csharp_alias_identifier(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches(';').trim();
    let rest = trimmed
        .strip_prefix("global ")
        .unwrap_or(trimmed)
        .strip_prefix("using ")?
        .trim();
    if rest.starts_with("static ") {
        return None;
    }
    let (alias, _) = rest.split_once('=')?;
    let alias = alias.trim();
    (!alias.is_empty()).then(|| alias.to_string())
}
