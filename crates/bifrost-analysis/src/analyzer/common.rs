pub(crate) use brokk_bifrost_core::analyzer::common::{
    max_line_length_limit, node_ident_text, node_source_text, node_source_text_trimmed,
};
// The line cap's only remaining in-crate readers are the three suites that
// build an over-long line to prove the parse guard fires; production reads it
// through `is_unparseable_source`.
#[cfg(test)]
pub(crate) use brokk_bifrost_core::analyzer::common::DEFAULT_MAX_LINE_LENGTH;
pub use brokk_bifrost_core::analyzer::common::{
    declaration_language_for_file, has_unclaimed_extension, is_unparseable_source,
    language_for_file, language_for_target, languages_may_analyze,
};
// Each language's identifier sigil moved with the language: Rust's to
// `brokk-bifrost-rust`, C#'s to `brokk-bifrost-csharp` (its one consumer,
// `graph::resolver::node_text`, moved with it). The segment-level `r#` strip
// went to core's `symbol_path`, where the client-selector normalizer that needs
// it lives.
pub(crate) use brokk_bifrost_rust::declarations::RUST_IDENTIFIER_SIGIL;

use crate::analyzer::{CodeUnit, Language, ProjectFile};
use std::path::Path;

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
    crate::analyzer::languages::language_support(language).map_or_else(
        || symbol.to_string(),
        |support| support.display_symbol_name(symbol),
    )
}

pub fn display_symbol_for_target(target: &CodeUnit) -> String {
    display_symbol_name(language_for_target(target), &target.fq_name())
}

/// The display symbol of the code unit's enclosing scope (the receiver/declaring type for
/// a method, the outer type for a nested type), or `None` for a top-level declaration.
///
/// Methods are not always lexically nested in their type (Go receivers, Rust `impl`,
/// C++ out-of-line definitions), so consumers can't reliably reconstruct the parent from
/// line spans. The hierarchy is encoded in `short_name` (members after `.`, nested types
/// via `$`), so we strip the last segment and re-qualify with the package.
///
/// Scala `object`s carry a trailing companion `$` on their own name segment (`Foo$`;
/// nested: `CharsetRange$.Atom$`, per `is_scala_object_like` above and
/// bifrost-jvm's `Companion` segment rendering). That trailing `$` is
/// self-decoration, not a hierarchy separator, so like TypeScript's `$static` suffix
/// above it must be stripped before the `rfind` cut -- otherwise it's read as the last
/// separator and an object names itself as its own parent (top-level `Probe$` -> `Some`
/// instead of `None`) or names its own display symbol instead of its enclosing scope
/// (`CharsetRange$.Atom$` -> itself instead of `CharsetRange`).
///
/// A `$` is a nesting join only *between* two names (C# `Outer$Inner`). At the
/// start of a segment it is identifier text (`angular.mock.$LogProvider`,
/// `$http`) -- the same misreading `split_segments_on_dollar` guards against on
/// the query side (#1057). Cutting there named `angular.mock.`, trailing
/// separator and all, as the parent.
pub(crate) fn display_parent_symbol_for_target(target: &CodeUnit) -> Option<String> {
    let short_storage;
    let short = if language_for_target(target) == Language::TypeScript {
        short_storage = target
            .short_name()
            .strip_suffix("$static")
            .unwrap_or(target.short_name())
            .to_string();
        short_storage.as_str()
    } else if language_for_target(target) == Language::Scala {
        short_storage = target
            .short_name()
            .strip_suffix('$')
            .unwrap_or(target.short_name())
            .to_string();
        short_storage.as_str()
    } else {
        target.short_name()
    };
    // fqname-M4: parent-of on the raw short_name string; runs on targets whose
    // fq is not threaded to this display helper.
    let cut = short
        .char_indices()
        .rev()
        .find(|&(index, ch)| match ch {
            '.' => true,
            '$' => !matches!(
                short[..index].chars().next_back(),
                None | Some('.') | Some('$')
            ),
            _ => false,
        })
        .map(|(index, _)| index)?;
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

/// The user-facing terminal name of `target`: its recorded terminal segment,
/// respelled the way its language displays a name.
///
/// The terminal boundary is read from the `CodeUnit`'s [`FqName`], never
/// re-derived by splitting the rendered short name on `.`. A terminal segment
/// may legitimately contain a dot or a slash -- a JS/TS object-literal key such
/// as `"data/web-interface.csv"` is one recorded `Member` segment -- and the
/// re-split named such a declaration `csv`, a name that addresses nothing:
/// outlines, document symbols, completion labels and the selector an agent
/// copies from them all pointed at a segment fragment (#2111).
///
/// [`FqName`]: brokk_bifrost_core::analyzer::fq_name::FqName
pub fn display_identifier_for_target(target: &CodeUnit) -> String {
    display_symbol_name(language_for_target(target), target.identifier())
}

pub fn source_identifier_for_target(target: &CodeUnit) -> &str {
    let identifier = target.identifier();
    crate::analyzer::languages::language_support(language_for_target(target))
        .map_or(identifier, |support| support.source_identifier(identifier))
}

/// Whether `identifier` is a spelling a caller can address `target` by: the
/// persisted `identifier`, or the source spelling
/// ([`source_identifier_for_target`]) when the two differ. This is exactly the
/// membership [`decorated_identifier_seeks`] widens the index seek to, so a
/// caller that re-filters seeked rows must use this and not `==` on the raw
/// identifier, or it narrows the seek back to the bug.
pub(crate) fn identifier_addresses_target(target: &CodeUnit, identifier: &str) -> bool {
    target.identifier() == identifier || source_identifier_for_target(target) == identifier
}

/// One key range in the persisted `(lang, identifier)` index.
///
/// `Prefix` is a half-open byte range over the same index, not a scan: see
/// [`decorated_identifier_seeks`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IdentifierSeek {
    Exact(String),
    /// Every identifier that starts with this string.
    Prefix(String),
}

/// The persisted `identifier` spellings, beyond `source_identifier` itself,
/// whose [`source_identifier_for_target`] is `source_identifier`. The exact
/// inverse of that function, per language.
///
/// Symbol lookup seeks the identifier index by the terminal segment of a query
/// path, and compares the rows it gets back against a declaration's lookup
/// aliases. Those aliases are derived from the *source* spelling: `#1063` made
/// the arity-free `Widget` an alias of the C# generic type indexed as
/// ``Widget`1``, and the `$`-splitting variant makes `create` an alias of the
/// TypeScript static member indexed as `create$static`. So an alias tail is
/// *not* always a spelling of the persisted identifier, and a seek for the
/// source spelling alone cannot see those declarations.
///
/// That matters beyond a missed candidate, because two gates in
/// `symbol_lookup` treat an indexed miss as conclusive rather than fall back to
/// a whole-workspace scan (`#1688`, `#1758`; the scan cost 194.3 s and 443.1 s
/// respectively on the measured workspaces). Both gates rest on exactly the
/// claim this function repairs: that seeking the query's terminal finds every
/// candidate an alias comparison could match.
///
/// The returned keys are a candidate filter, never the answer. A prefix range
/// admits spellings that are not decorations at all (``Widget`x`` is not a
/// generic arity), so the caller must still compare
/// `source_identifier_for_target` on each row -- the same seek-then-verify
/// discipline `sql_search_definitions_by_suffix_pattern` uses.
pub(crate) fn decorated_identifier_seeks(
    language: Language,
    source_identifier: &str,
) -> Vec<IdentifierSeek> {
    if source_identifier.is_empty() {
        return Vec::new();
    }
    match language {
        // A generic type or method carries CLR arity: `Widget`1`, and
        // `Widget``2` for a generic method's own parameters. Arity is a digit
        // run of no fixed length, so the decorated spellings are a prefix
        // range rather than an enumerable set.
        Language::CSharp => vec![IdentifierSeek::Prefix(format!("{source_identifier}`"))],
        Language::TypeScript => vec![IdentifierSeek::Exact(format!("{source_identifier}$static"))],
        // A Scala object is indexed with a trailing `$` that its display form
        // drops (`LabelEquivalenceRelation$`); nobody types the marker, so the
        // source spelling's seek must name the decorated row (#2419).
        Language::Scala => vec![IdentifierSeek::Exact(format!("{source_identifier}$"))],
        _ => Vec::new(),
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
    let Some(parser_language) = super::parser_language_for(language) else {
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

/// One unit of pending skeleton-rendering work.
enum SkeletonWork {
    /// Emit `unit`'s signatures, then enqueue its children.
    Render { unit: CodeUnit, indent: String },
    /// Emit the trailing `[...]` elision marker and/or closing brace that
    /// follow a unit's children.
    Close {
        indent: String,
        child_indent: String,
        elide: bool,
        close_brace: bool,
    },
}

/// Render `code_unit`'s skeleton — its signature, then its children indented
/// beneath it, closing class-like units with `}`.
///
/// `header_only` keeps just the field children and marks the elided remainder
/// with `[...]`.
///
/// Shared by the language analyzers that override `direct_children` (to hide
/// synthetic units) and therefore cannot use the engine's own renderer, which
/// reads `TreeSitterAnalyzer::direct_children` directly. Dispatching through
/// `&dyn IAnalyzer` here means each analyzer's overrides still apply.
///
/// Iterative rather than recursive: declaration nesting is attacker-controlled
/// (a generated or hostile source file can nest types thousands deep), so a
/// recursive walk risks exhausting the native stack.
pub(crate) fn render_skeleton(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    code_unit: &CodeUnit,
    header_only: bool,
) -> String {
    let mut out = String::new();
    let mut stack = vec![SkeletonWork::Render {
        unit: code_unit.clone(),
        indent: String::new(),
    }];

    while let Some(work) = stack.pop() {
        match work {
            SkeletonWork::Render { unit, indent } => {
                for signature in analyzer.signatures(&unit) {
                    if signature.is_empty() {
                        continue;
                    }
                    for line in signature.lines() {
                        out.push_str(&indent);
                        out.push_str(line);
                        out.push('\n');
                    }
                }

                let all_children = analyzer.direct_children(&unit);
                let all_child_count = all_children.len();
                let is_class = unit.is_class();
                let children: Vec<CodeUnit> = if header_only {
                    all_children
                        .into_iter()
                        .filter(CodeUnit::is_field)
                        .collect()
                } else {
                    all_children
                };

                if children.is_empty() && !is_class {
                    continue;
                }
                let child_indent = format!("{indent}  ");
                // Pushed before the children so it pops after them. The
                // elision marker compares against the pre-filter child count,
                // so it fires exactly when `header_only` dropped something.
                stack.push(SkeletonWork::Close {
                    indent,
                    child_indent: child_indent.clone(),
                    elide: header_only && all_child_count > children.len(),
                    close_brace: is_class,
                });
                for child in children.into_iter().rev() {
                    stack.push(SkeletonWork::Render {
                        unit: child,
                        indent: child_indent.clone(),
                    });
                }
            }
            SkeletonWork::Close {
                indent,
                child_indent,
                elide,
                close_brace,
            } => {
                if elide {
                    out.push_str(&child_indent);
                    out.push_str("[...]\n");
                }
                if close_brace {
                    out.push_str(&indent);
                    out.push_str("}\n");
                }
            }
        }
    }

    out
}

pub(crate) fn is_scala_object_like(target: &CodeUnit) -> bool {
    language_for_target(target) == Language::Scala && (target.is_class() || target.is_module()) && {
        // A `.`-joined short_name segment "ending in `$`" is exactly a
        // Scala companion-object segment: Scala's only `$`-spelling is
        // the `Companion` kind's trailing suffix on its own segment text
        // (never a join, and Scala never emits `Nested`), so walking the
        // unit's structured `fq()` for a `Companion` segment reproduces
        // the string check exactly without re-splitting the rendered name.
        let interner = crate::analyzer::fq_name::segment_interner();
        target
            .fq()
            .segments()
            .iter()
            .any(|&id| interner.resolve(id).1 == crate::analyzer::fq_name::SegmentKind::Companion)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_MAX_LINE_LENGTH, display_parent_symbol_for_target, display_symbol_name,
        is_unparseable_source, is_valid_rename_identifier,
    };
    use crate::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
    use crate::analyzer::{CodeUnit, CodeUnitType, Language, ProjectFile};

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
    fn scala_companion_dollar_is_not_read_as_a_parent_separator() {
        let root = std::env::temp_dir().join("bifrost-common-scala-parent-test");
        let interner = segment_interner();

        // Top-level `object Probe` -> short_name "Probe$": the trailing `$` must
        // not be read as a separator, so there is no parent.
        let mut top_level_fq = FqName::new();
        top_level_fq.push(interner.intern("com.example", SegmentKind::Package));
        top_level_fq.push(interner.intern("Probe", SegmentKind::Companion));
        let top_level = CodeUnit::from_fq(
            ProjectFile::new(&root, "Probe.scala"),
            CodeUnitType::Class,
            top_level_fq,
            1,
            None,
            false,
        );
        assert_eq!(None, display_parent_symbol_for_target(&top_level));

        // `object CharsetRange { object Atom }` -> short_name
        // "CharsetRange$.Atom$": the parent is the enclosing object
        // "org.http4s.CharsetRange", not the target's own display symbol.
        let mut nested_fq = FqName::new();
        nested_fq.push(interner.intern("org.http4s", SegmentKind::Package));
        nested_fq.push(interner.intern("CharsetRange", SegmentKind::Companion));
        nested_fq.push(interner.intern("Atom", SegmentKind::Companion));
        let nested = CodeUnit::from_fq(
            ProjectFile::new(&root, "CharsetRange.scala"),
            CodeUnitType::Class,
            nested_fq,
            1,
            None,
            false,
        );
        assert_eq!(
            Some("org.http4s.CharsetRange".to_string()),
            display_parent_symbol_for_target(&nested)
        );
    }

    #[test]
    fn leading_dollar_in_a_terminal_identifier_is_not_a_parent_separator() {
        let root = std::env::temp_dir().join("bifrost-common-js-parent-test");
        let interner = segment_interner();

        // `angular.mock.$LogProvider = function() {...}` -> the terminal
        // identifier starts with `$`. That `$` is identifier text, not a
        // nesting join, so the parent is `angular.mock`, not `angular.mock.`.
        let mut fq = FqName::new();
        fq.push(interner.intern("angular.mock", SegmentKind::Member));
        fq.push(interner.intern("$LogProvider", SegmentKind::Member));
        let member = CodeUnit::from_fq(
            ProjectFile::new(&root, "angular-mocks.js"),
            CodeUnitType::Function,
            fq,
            0,
            None,
            false,
        );
        assert_eq!(
            Some("angular.mock".to_string()),
            display_parent_symbol_for_target(&member)
        );

        // A bare `$`-prefixed top-level function has no parent at all.
        let mut top_level_fq = FqName::new();
        top_level_fq.push(interner.intern("$LogProvider", SegmentKind::Member));
        let top_level = CodeUnit::from_fq(
            ProjectFile::new(&root, "log.js"),
            CodeUnitType::Function,
            top_level_fq,
            0,
            None,
            false,
        );
        assert_eq!(None, display_parent_symbol_for_target(&top_level));
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
