use lsp_types::{
    DocumentSymbol, DocumentSymbolParams, DocumentSymbolResponse, Range as LspRange, SymbolKind,
};

use crate::analyzer::common::display_identifier_for_target;
use crate::analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, Project, Range as ByteRange, WorkspaceAnalyzer,
};
use crate::lsp::conversion::byte_range_to_lsp_range;
use crate::lsp::handlers::util::{find_word, identifier_selection_range, read_document_for_uri};
use crate::text_utils::compute_line_starts;

/// Build the documentSymbol response for a request URI. Returns `None` when
/// the URI does not map into the active project root, or when the file is
/// not analyzed by any of the workspace's per-language analyzers.
pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &DocumentSymbolParams,
) -> Option<DocumentSymbolResponse> {
    let (project_file, content, line_starts) =
        read_document_for_uri(project, &params.text_document.uri)?;
    let analyzer = workspace.analyzer();

    let top_level: Vec<CodeUnit> = analyzer
        .top_level_declarations(&project_file)
        .filter(|cu| !cu.is_anonymous())
        .cloned()
        .collect();
    let symbols = build_symbols_iterative(analyzer, top_level, &content, &line_starts);

    Some(DocumentSymbolResponse::Nested(symbols))
}

fn build_symbols_iterative(
    analyzer: &dyn IAnalyzer,
    roots: Vec<CodeUnit>,
    content: &str,
    line_starts: &[usize],
) -> Vec<DocumentSymbol> {
    let mut completed = Vec::new();
    let mut stack: Vec<SymbolWorkItem> = roots
        .into_iter()
        .rev()
        .map(|code_unit| SymbolWorkItem::Enter(code_unit, None))
        .collect();

    while let Some(item) = stack.pop() {
        match item {
            SymbolWorkItem::Enter(code_unit, parent_kind) => {
                let parts =
                    lsp_symbol_parts(analyzer, &code_unit, content, line_starts, parent_kind);
                let child_parent_kind = Some(parts.kind);
                let children: Vec<CodeUnit> = analyzer
                    .direct_children(&code_unit)
                    .filter(|child| !child.is_anonymous())
                    .cloned()
                    .collect();
                let child_count = children.len();
                stack.push(SymbolWorkItem::Exit { parts, child_count });
                for child in children.into_iter().rev() {
                    stack.push(SymbolWorkItem::Enter(child, child_parent_kind));
                }
            }
            SymbolWorkItem::Exit { parts, child_count } => {
                let split_at = completed.len().saturating_sub(child_count);
                let children = completed.split_off(split_at);
                completed.push(symbol_from_parts(parts, children));
            }
        }
    }

    completed
}

enum SymbolWorkItem {
    Enter(CodeUnit, Option<SymbolKind>),
    Exit {
        parts: LspSymbolParts,
        child_count: usize,
    },
}

fn symbol_from_parts(parts: LspSymbolParts, children: Vec<DocumentSymbol>) -> DocumentSymbol {
    #[allow(deprecated)] // `deprecated` field is present on lsp-types DocumentSymbol.
    DocumentSymbol {
        name: parts.name,
        detail: parts.detail,
        kind: parts.kind,
        tags: None,
        deprecated: None,
        range: parts.range,
        selection_range: parts.selection_range,
        children: if children.is_empty() {
            None
        } else {
            Some(children)
        },
    }
}

pub(super) struct LspSymbolParts {
    pub(super) name: String,
    pub(super) detail: Option<String>,
    pub(super) kind: SymbolKind,
    pub(super) range: LspRange,
    pub(super) selection_range: LspRange,
}

pub(super) fn lsp_symbol_parts(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    content: &str,
    line_starts: &[usize],
    parent_kind: Option<SymbolKind>,
) -> LspSymbolParts {
    let range = primary_range(analyzer, code_unit, content);
    let lsp_range = byte_range_to_lsp_range(content, line_starts, &range);
    let selection_range =
        identifier_selection_range(code_unit, content, line_starts, &range).unwrap_or(lsp_range);

    LspSymbolParts {
        name: display_identifier_for_target(code_unit),
        detail: code_unit.signature().map(str::to_string),
        kind: classify_symbol_kind(code_unit, parent_kind),
        range: lsp_range,
        selection_range,
    }
}

pub(super) fn primary_range(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    content: &str,
) -> ByteRange {
    // Prefer the analyzer's recorded range; fall back to the whole file if the
    // analyzer has no range info (synthetic units, modules, etc.).
    analyzer
        .ranges(code_unit)
        .iter()
        .min()
        .copied()
        .unwrap_or(ByteRange {
            start_byte: 0,
            end_byte: content.len(),
            start_line: 0,
            end_line: line_count(content),
        })
}

/// Map a code unit to its richest LSP `SymbolKind`. The analyzer only stores
/// four coarse kinds (Class/Function/Field/Module), but tree-sitter signatures
/// preserve the keyword that introduced the declaration (`interface`, `enum`,
/// `struct`, `record`, `trait`) and naming conventions disambiguate
/// constructors, constants, and enum members. `parent_kind` carries the
/// already-classified kind of the enclosing symbol so we can promote fields
/// of an enum to `EnumMember` and methods named after their enclosing type to
/// `Constructor`.
pub(super) fn classify_symbol_kind(
    code_unit: &CodeUnit,
    parent_kind: Option<SymbolKind>,
) -> SymbolKind {
    match code_unit.kind() {
        CodeUnitType::Class => classify_class_like(code_unit.signature()),
        CodeUnitType::Function => {
            if is_constructor(code_unit, parent_kind) {
                SymbolKind::CONSTRUCTOR
            } else {
                SymbolKind::FUNCTION
            }
        }
        CodeUnitType::Method => {
            if is_constructor(code_unit, parent_kind) {
                SymbolKind::CONSTRUCTOR
            } else {
                SymbolKind::METHOD
            }
        }
        CodeUnitType::Field => {
            if parent_kind == Some(SymbolKind::ENUM) {
                SymbolKind::ENUM_MEMBER
            } else if is_constant(code_unit) {
                SymbolKind::CONSTANT
            } else {
                SymbolKind::VARIABLE
            }
        }
        CodeUnitType::Module => SymbolKind::MODULE,
        CodeUnitType::Macro => SymbolKind::CONSTANT,
        CodeUnitType::FileScope => SymbolKind::FILE,
    }
}

/// Inspect the leading keyword of a class-like declaration's signature to
/// decide which LSP kind best represents it. The signature includes modifiers
/// and the introducing keyword, e.g. `public interface Foo {`, `pub enum Bar`,
/// `struct S {`, so a word-boundary scan picks out the right keyword without
/// being fooled by identifiers like `enumerable` or `traits`.
fn classify_class_like(signature: Option<&str>) -> SymbolKind {
    let Some(sig) = signature else {
        return SymbolKind::CLASS;
    };
    if find_word(sig, "interface").is_some() || find_word(sig, "trait").is_some() {
        SymbolKind::INTERFACE
    } else if find_word(sig, "enum").is_some() {
        SymbolKind::ENUM
    } else if find_word(sig, "struct").is_some() || find_word(sig, "record").is_some() {
        SymbolKind::STRUCT
    } else {
        SymbolKind::CLASS
    }
}

fn is_constructor(code_unit: &CodeUnit, parent_kind: Option<SymbolKind>) -> bool {
    // Only types that can actually declare constructors qualify. INTERFACE is
    // intentionally excluded: Java/C# interfaces can't have constructors, and
    // a TS interface member literally named `constructor` would be unusual —
    // promoting it would just produce wrong icons.
    if !matches!(
        parent_kind,
        Some(SymbolKind::CLASS) | Some(SymbolKind::STRUCT) | Some(SymbolKind::ENUM)
    ) {
        return false;
    }
    let identifier = code_unit.identifier();
    // Language-level constructor names: TS `constructor`, Python `__init__`,
    // PHP `__construct`. Java/C# constructors have the same name as their
    // enclosing type, which (because short_name is built as
    // `parent_short_name.method_name`) shows up as the last two
    // dot-separated segments being equal.
    matches!(identifier, "__init__" | "__construct" | "constructor")
        || constructor_matches_owner(code_unit)
}

fn constructor_matches_owner(code_unit: &CodeUnit) -> bool {
    let mut parts = code_unit.short_name().rsplit('.');
    let last = parts.next();
    let prev = parts.next();
    matches!((prev, last), (Some(parent), Some(method)) if !parent.is_empty() && parent == method)
}

fn is_constant(code_unit: &CodeUnit) -> bool {
    let identifier = code_unit.identifier();
    if is_screaming_snake_case(identifier) {
        return true;
    }
    let Some(sig) = code_unit.signature() else {
        return false;
    };
    if find_word(sig, "const").is_some() {
        return true;
    }
    // Java instance `final` (e.g. `private final List<String> names`) is just
    // single-assignment, not a compile-time constant — `static final` together
    // is what really means CONSTANT. TS `readonly` similarly only means
    // "can't be reassigned post-init", so it's intentionally not handled here.
    find_word(sig, "static").is_some() && find_word(sig, "final").is_some()
}

fn is_screaming_snake_case(identifier: &str) -> bool {
    if identifier.is_empty() {
        return false;
    }
    let mut alpha_count = 0usize;
    for ch in identifier.chars() {
        if ch.is_ascii_uppercase() {
            alpha_count += 1;
        } else if !ch.is_ascii_digit() && ch != '_' {
            return false;
        }
    }
    if alpha_count == 0 {
        return false;
    }
    // Genuine SCREAMING_SNAKE_CASE either has a separator or at least two
    // letters. Single-letter all-caps names like `X` or `T` (typical generic
    // parameters or one-letter fields) should not be promoted to CONSTANT.
    identifier.contains('_') || alpha_count >= 2
}

fn line_count(content: &str) -> usize {
    if content.is_empty() {
        0
    } else {
        compute_line_starts(content).len().saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::ProjectFile;

    #[test]
    fn find_word_skips_substring_match_inside_longer_identifier() {
        // The naive `find` would return offset 0 (the `foo` prefix of
        // `foofoo`); find_word must skip ahead to the standalone `foo`.
        assert_eq!(find_word("foofoo + foo;", "foo"), Some(9));
    }

    #[test]
    fn find_word_skips_substring_match_in_keyword() {
        // Method named `s` should not select the `s` in `class`.
        assert_eq!(find_word("class Demo { void s() {} }", "s"), Some(18));
    }

    #[test]
    fn find_word_returns_none_when_no_word_match_exists() {
        assert_eq!(find_word("foofoo", "foo"), None);
        assert_eq!(find_word("classify", "class"), None);
    }

    #[test]
    fn find_word_anchors_at_buffer_edges() {
        assert_eq!(find_word("foo", "foo"), Some(0));
        assert_eq!(find_word("a foo", "foo"), Some(2));
        assert_eq!(find_word("foo bar", "foo"), Some(0));
    }

    fn project_file() -> ProjectFile {
        let root = if cfg!(windows) {
            std::path::PathBuf::from("C:\\tmp")
        } else {
            std::path::PathBuf::from("/tmp")
        };
        ProjectFile::new(root, "Foo.txt")
    }

    fn function_with(short_name: &str, signature: Option<&str>) -> CodeUnit {
        CodeUnit::with_signature(
            project_file(),
            CodeUnitType::Function,
            "",
            short_name,
            signature.map(str::to_string),
            false,
        )
    }

    fn field_with(short_name: &str, signature: Option<&str>) -> CodeUnit {
        CodeUnit::with_signature(
            project_file(),
            CodeUnitType::Field,
            "",
            short_name,
            signature.map(str::to_string),
            false,
        )
    }

    #[test]
    fn class_like_signatures_promote_to_specific_kinds() {
        assert_eq!(
            classify_class_like(Some("public interface Greeter {")),
            SymbolKind::INTERFACE,
        );
        assert_eq!(
            classify_class_like(Some("pub trait Drawable {")),
            SymbolKind::INTERFACE,
        );
        assert_eq!(
            classify_class_like(Some("pub enum Color { Red, Green }")),
            SymbolKind::ENUM,
        );
        assert_eq!(
            classify_class_like(Some("pub struct Point { x: f64 }")),
            SymbolKind::STRUCT,
        );
        assert_eq!(
            classify_class_like(Some("public record Pair(int a, int b) {")),
            SymbolKind::STRUCT,
        );
        assert_eq!(
            classify_class_like(Some("public class Greeter {")),
            SymbolKind::CLASS,
        );
        assert_eq!(classify_class_like(None), SymbolKind::CLASS);
    }

    #[test]
    fn class_like_keyword_match_is_word_bounded() {
        // `enumerable` must NOT be picked up as `enum`.
        assert_eq!(
            classify_class_like(Some("class Enumerable {")),
            SymbolKind::CLASS,
        );
    }

    #[test]
    fn java_constructor_is_detected_when_method_name_matches_owner() {
        let constructor = function_with("Foo.Foo", Some("public Foo()"));
        assert_eq!(
            classify_symbol_kind(&constructor, Some(SymbolKind::CLASS)),
            SymbolKind::CONSTRUCTOR,
        );
        // Same short_name without a class parent — fall back to FUNCTION.
        assert_eq!(
            classify_symbol_kind(&constructor, None),
            SymbolKind::FUNCTION,
        );
    }

    #[test]
    fn special_constructor_names_are_detected() {
        for name in ["__init__", "__construct", "constructor"] {
            let func = function_with(&format!("Foo.{name}"), Some("..."));
            assert_eq!(
                classify_symbol_kind(&func, Some(SymbolKind::CLASS)),
                SymbolKind::CONSTRUCTOR,
                "{name} should classify as constructor",
            );
        }
    }

    #[test]
    fn interface_parent_does_not_promote_to_constructor() {
        // Interfaces can't have constructors; a TS interface member literally
        // named `constructor` should stay FUNCTION.
        let func = function_with("Foo.constructor", Some("constructor(): void;"));
        assert_eq!(
            classify_symbol_kind(&func, Some(SymbolKind::INTERFACE)),
            SymbolKind::FUNCTION,
        );
    }

    #[test]
    fn ordinary_function_stays_function() {
        let func = function_with("Foo.bar", Some("fn bar()"));
        assert_eq!(
            classify_symbol_kind(&func, Some(SymbolKind::CLASS)),
            SymbolKind::FUNCTION,
        );
    }

    #[test]
    fn enum_field_is_promoted_to_enum_member() {
        let variant = field_with("Color.Red", None);
        assert_eq!(
            classify_symbol_kind(&variant, Some(SymbolKind::ENUM)),
            SymbolKind::ENUM_MEMBER,
        );
    }

    #[test]
    fn screaming_snake_case_field_is_constant() {
        let f = field_with("Foo.MAX_SIZE", Some("private static int MAX_SIZE = 10;"));
        assert_eq!(
            classify_symbol_kind(&f, Some(SymbolKind::CLASS)),
            SymbolKind::CONSTANT,
        );
    }

    #[test]
    fn final_or_const_keyword_makes_field_constant() {
        let java_final = field_with("Foo.size", Some("public static final int size = 10;"));
        assert_eq!(
            classify_symbol_kind(&java_final, Some(SymbolKind::CLASS)),
            SymbolKind::CONSTANT,
        );
        let rust_const = field_with("Foo.SIZE", Some("pub const SIZE: usize = 10"));
        assert_eq!(
            classify_symbol_kind(&rust_const, Some(SymbolKind::CLASS)),
            SymbolKind::CONSTANT,
        );
    }

    #[test]
    fn java_instance_final_field_is_not_constant() {
        // `private final List<String> names = new ArrayList<>();` is single-
        // assignment but not a compile-time constant — only `static final`
        // together earns CONSTANT.
        let f = field_with(
            "Foo.names",
            Some("private final List<String> names = new ArrayList<>();"),
        );
        assert_eq!(
            classify_symbol_kind(&f, Some(SymbolKind::CLASS)),
            SymbolKind::VARIABLE,
        );
    }

    #[test]
    fn ts_readonly_instance_field_is_not_constant() {
        let f = field_with("Foo.name", Some("readonly name: string;"));
        assert_eq!(
            classify_symbol_kind(&f, Some(SymbolKind::CLASS)),
            SymbolKind::VARIABLE,
        );
    }

    #[test]
    fn ordinary_field_is_variable() {
        let f = field_with("Foo.count", Some("private int count;"));
        assert_eq!(
            classify_symbol_kind(&f, Some(SymbolKind::CLASS)),
            SymbolKind::VARIABLE,
        );
    }

    #[test]
    fn screaming_snake_case_rejects_lowercase() {
        assert!(is_screaming_snake_case("MAX_SIZE"));
        assert!(is_screaming_snake_case("MAX"));
        assert!(is_screaming_snake_case("X_1"));
        assert!(!is_screaming_snake_case(""));
        assert!(!is_screaming_snake_case("_"));
        assert!(!is_screaming_snake_case("Max"));
        assert!(!is_screaming_snake_case("max_size"));
    }

    #[test]
    fn screaming_snake_case_rejects_single_letter_names() {
        // Single uppercase identifiers (generic params, one-letter fields)
        // should not classify as SCREAMING_SNAKE_CASE.
        assert!(!is_screaming_snake_case("X"));
        assert!(!is_screaming_snake_case("T"));
    }

    #[test]
    fn module_kind_passes_through() {
        let m = CodeUnit::with_signature(
            project_file(),
            CodeUnitType::Module,
            "",
            "my_mod",
            Some("mod my_mod {".to_string()),
            false,
        );
        assert_eq!(classify_symbol_kind(&m, None), SymbolKind::MODULE);
    }

    #[test]
    fn class_inside_class_does_not_trigger_constructor_for_field() {
        // A field whose short_name path looks like a constructor (last two
        // segments equal) should still classify as VARIABLE, not CONSTRUCTOR —
        // the constructor rule only applies to functions.
        let f = field_with("Foo.Foo", Some("private int Foo;"));
        assert_eq!(
            classify_symbol_kind(&f, Some(SymbolKind::CLASS)),
            SymbolKind::VARIABLE,
        );
    }
}
