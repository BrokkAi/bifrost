use crate::analyzer::{CodeUnit, Language, ProjectFile};

pub(crate) fn language_for_target(target: &CodeUnit) -> Language {
    language_for_file(target.source())
}

pub(crate) fn language_for_file(file: &ProjectFile) -> Language {
    file.rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

pub(crate) fn display_symbol_name(language: Language, symbol: &str) -> String {
    match language {
        Language::Scala => symbol
            .split('.')
            .map(|segment| segment.trim_end_matches('$'))
            .collect::<Vec<_>>()
            .join("."),
        _ => symbol.to_string(),
    }
}

pub(crate) fn display_symbol_for_target(target: &CodeUnit) -> String {
    display_symbol_name(language_for_target(target), &target.fq_name())
}

pub(crate) fn display_identifier_for_target(target: &CodeUnit) -> String {
    let display_name = display_symbol_name(language_for_target(target), target.short_name());
    display_name
        .rsplit('.')
        .next()
        .unwrap_or(&display_name)
        .to_string()
}

pub(crate) fn is_scala_object_like(target: &CodeUnit) -> bool {
    language_for_target(target) == Language::Scala
        && (target.is_class() || target.is_module())
        && target
            .short_name()
            .split('.')
            .any(|segment| segment.ends_with('$'))
}
