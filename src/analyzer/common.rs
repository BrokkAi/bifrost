use crate::analyzer::{CodeUnit, Language, ProjectFile};
use std::path::Path;
use tree_sitter::Language as TsLanguage;

/// Default longest single line a source file may contain before tree-sitter parsing is
/// skipped. Minified/generated single-line bundles (committed webpack output, mermaid.min.js,
/// etc.) have 16KB+ lines and otherwise both livelock the parser and explode downstream
/// consumers (e.g. the semantic indexer extracting thousands of bogus chunks). Hand-written
/// and normally-formatted generated source stays far below this, so the cap is effectively
/// invisible to real code. 16000 is comfortably above any human-authored line while still
/// catching moderately-sized minified bundles that a higher cap would let through.
pub(crate) const DEFAULT_MAX_LINE_LENGTH: usize = 16_000;

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

pub(crate) fn rebase_project_file_to_root(file: &ProjectFile, root: &Path) -> Option<ProjectFile> {
    if file.root() == root {
        return Some(file.clone());
    }
    let abs_path = file.abs_path();
    let rel = if let Ok(rel) = abs_path.strip_prefix(root) {
        rel.to_path_buf()
    } else {
        let canonical_abs = abs_path.canonicalize().ok()?;
        let canonical_root = root.canonicalize().ok()?;
        canonical_abs
            .strip_prefix(canonical_root)
            .ok()?
            .to_path_buf()
    };
    Some(ProjectFile::new(root.to_path_buf(), rel))
}

pub(crate) fn display_symbol_name(language: Language, symbol: &str) -> String {
    match language {
        Language::Scala => symbol
            .split('.')
            .map(|segment| segment.trim_end_matches('$'))
            .collect::<Vec<_>>()
            .join("."),
        Language::CSharp => crate::analyzer::csharp_normalize_full_name(symbol),
        Language::TypeScript => symbol.strip_suffix("$static").unwrap_or(symbol).to_string(),
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
    let short_storage;
    let short = if language_for_target(target) == Language::TypeScript {
        short_storage = target
            .short_name()
            .strip_suffix("$static")
            .unwrap_or(target.short_name())
            .to_string();
        short_storage.as_str()
    } else {
        target.short_name()
    };
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

pub(crate) fn source_identifier_for_target(target: &CodeUnit) -> &str {
    let identifier = target.identifier();
    match language_for_target(target) {
        Language::CSharp => crate::analyzer::csharp::strip_csharp_generic_arity(identifier),
        Language::TypeScript => identifier.strip_suffix("$static").unwrap_or(identifier),
        _ => identifier,
    }
}

pub(crate) fn is_valid_rename_identifier(language: Language, name: &str) -> bool {
    is_identifier_text(name) && !is_reserved_identifier(language, name)
}

fn is_identifier_text(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_alphabetic()) && chars.all(|ch| ch == '_' || ch.is_alphanumeric())
}

fn is_reserved_identifier(language: Language, name: &str) -> bool {
    let Some(parser_language) = parser_language_for(language) else {
        return false;
    };
    (0..parser_language.node_kind_count()).any(|id| {
        let Ok(id) = u16::try_from(id) else {
            return false;
        };
        !parser_language.node_kind_is_named(id)
            && parser_language.node_kind_for_id(id) == Some(name)
    })
}

fn parser_language_for(language: Language) -> Option<TsLanguage> {
    Some(match language {
        Language::Java => tree_sitter_java::LANGUAGE.into(),
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        Language::Scala => tree_sitter_scala::LANGUAGE.into(),
        Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        Language::Ruby => tree_sitter_ruby::LANGUAGE.into(),
        Language::None => return None,
    })
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
    use super::{
        DEFAULT_MAX_LINE_LENGTH, display_symbol_name, is_unparseable_source,
        is_valid_rename_identifier,
    };
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

    #[test]
    fn rename_identifier_validation_uses_language_grammar_keywords() {
        assert!(is_valid_rename_identifier(Language::Java, "renamed_1"));
        assert!(is_valid_rename_identifier(Language::Java, "café"));
        assert!(!is_valid_rename_identifier(Language::Java, ""));
        assert!(!is_valid_rename_identifier(Language::Java, "1renamed"));
        assert!(!is_valid_rename_identifier(Language::Java, "renamed-name"));
        assert!(!is_valid_rename_identifier(Language::Java, "class"));
        assert!(!is_valid_rename_identifier(Language::Cpp, "namespace"));
        assert!(!is_valid_rename_identifier(Language::Python, "def"));
        assert!(!is_valid_rename_identifier(Language::Rust, "fn"));
    }
}
