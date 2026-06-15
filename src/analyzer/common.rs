use crate::analyzer::{CodeUnit, Language, ProjectFile};

/// Longest single line a source file may contain before tree-sitter parsing is
/// skipped, from `BIFROST_MAX_LINE_LENGTH` (unset = no limit). Minified/generated
/// single-line bundles (e.g. committed webpack output) otherwise livelock the
/// parser. 20000 mirrors VS Code's `editor.maxTokenizationLineLength`.
pub(crate) fn max_line_length_limit() -> Option<usize> {
    std::env::var("BIFROST_MAX_LINE_LENGTH")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
}

/// Whether `source` must NOT be handed to tree-sitter: it is binary (contains NUL
/// bytes) or pathological for the parser (a line longer than the configured cap).
/// Centralizes the "is this safe to parse?" decision for every parse site so no
/// consumer livelocks on adversarial input.
pub(crate) fn is_unparseable_source(source: &str) -> bool {
    if source.as_bytes().contains(&0) {
        return true;
    }
    match max_line_length_limit() {
        Some(limit) => source.lines().any(|line| line.len() > limit),
        None => false,
    }
}

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
        Language::CSharp => symbol
            .split('.')
            .map(|segment| segment.replace('$', "."))
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

#[cfg(test)]
mod tests {
    use super::display_symbol_name;
    use crate::analyzer::Language;

    #[test]
    fn display_symbol_name_normalizes_scala_and_csharp_user_facing_names() {
        assert_eq!(
            "ai.brokk.ir.PrimOp.AsClockOp",
            display_symbol_name(Language::Scala, "ai.brokk.ir$.PrimOp$.AsClockOp$")
        );
        assert_eq!(
            "N.Outer.Inner.Method",
            display_symbol_name(Language::CSharp, "N.Outer$Inner.Method")
        );
    }
}
