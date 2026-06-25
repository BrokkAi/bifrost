use crate::analyzer::{CodeUnit, Language, ProjectFile};

/// Default longest single line a source file may contain before tree-sitter parsing is
/// skipped. Minified/generated single-line bundles (committed webpack output, mermaid.min.js,
/// etc.) have 100KB+ lines and otherwise both livelock the parser and explode downstream
/// consumers (e.g. the semantic indexer extracting thousands of bogus chunks). Hand-written
/// and normally-formatted generated source stays far below this, so the cap is effectively
/// invisible to real code. 50000 matches the diff long-line threshold used elsewhere and sits
/// well above VS Code's 20000 `editor.maxTokenizationLineLength`.
pub(crate) const DEFAULT_MAX_LINE_LENGTH: usize = 50_000;

/// Longest single line a source file may contain before tree-sitter parsing is skipped.
/// Defaults to [`DEFAULT_MAX_LINE_LENGTH`]; `BIFROST_MAX_LINE_LENGTH` overrides it, and an
/// explicit `0` disables the limit entirely (parse everything, at your own risk).
pub(crate) fn max_line_length_limit() -> Option<usize> {
    match std::env::var("BIFROST_MAX_LINE_LENGTH") {
        Ok(v) => match v.trim().parse::<usize>() {
            Ok(0) => None,
            Ok(n) => Some(n),
            Err(_) => Some(DEFAULT_MAX_LINE_LENGTH),
        },
        Err(_) => Some(DEFAULT_MAX_LINE_LENGTH),
    }
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

/// The display symbol of the code unit's enclosing scope (the receiver/declaring type for
/// a method, the outer type for a nested type), or `None` for a top-level declaration.
///
/// Methods are not always lexically nested in their type (Go receivers, Rust `impl`,
/// C++ out-of-line definitions), so consumers can't reliably reconstruct the parent from
/// line spans. The hierarchy is encoded in `short_name` (members after `.`, nested types
/// via `$`), so we strip the last segment and re-qualify with the package.
pub(crate) fn display_parent_symbol_for_target(target: &CodeUnit) -> Option<String> {
    let short = target.short_name();
    let cut = short.rfind(['.', '$'])?;
    let parent_short = &short[..cut];
    if parent_short.is_empty() {
        return None;
    }
    let package = target.package_name();
    let parent_fq = if package.is_empty() {
        parent_short.to_string()
    } else {
        format!("{package}.{parent_short}")
    };
    Some(display_symbol_name(language_for_target(target), &parent_fq))
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
    use super::{DEFAULT_MAX_LINE_LENGTH, display_symbol_name, is_unparseable_source};
    use crate::analyzer::Language;

    #[test]
    fn minified_and_binary_sources_are_unparseable_by_default() {
        // Assumes BIFROST_MAX_LINE_LENGTH is unset (the normal test environment), so the
        // default cap applies. A single line past the cap = minified bundle = skip.
        let minified = format!("var x=1;{}", "a".repeat(DEFAULT_MAX_LINE_LENGTH + 1));
        assert!(is_unparseable_source(&minified));

        // Normal multi-line source stays parseable.
        let normal: String = (0..2000).map(|i| format!("let v{i} = {i};\n")).collect();
        assert!(!is_unparseable_source(&normal));

        // NUL bytes => binary => unparseable regardless of line length.
        assert!(is_unparseable_source("fn main() {\0}"));
    }

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
