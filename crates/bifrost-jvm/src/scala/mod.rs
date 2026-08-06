//! Scala language knowledge.

pub mod adapter;
pub mod clones;
pub mod declarations;
pub mod diagnostics;
pub mod graph;
pub mod graph_support;
pub mod imports;
pub mod language;
pub mod structural;
pub mod supertypes;
pub mod test_detection;
pub mod wildcard_imports;

use brokk_bifrost_core::analyzer::{CodeUnit, Language};

/// Strip the `$` companion-object spelling out of a Scala fully qualified name.
pub fn scala_normalize_full_name(fq_name: &str) -> String {
    fq_name.replace("$.", ".").trim_end_matches('$').to_string()
}

/// Candidate spellings of `segments` rooted at `prefix`, plus the "$"
/// companion-object spelling Scala singletons use in fqns.
///
/// `prefix_is_owner` distinguishes an owner whose *own* spelling still needs
/// a trailing `$` inserted (an object/class fqn segment used as a qualifying
/// prefix) from a prefix that already carries its correct spelling (e.g. a
/// package name, or another candidate's fqn taken as-is).
pub fn scala_nested_type_candidates(
    prefix: String,
    segments: &[String],
    prefix_is_owner: bool,
) -> Vec<String> {
    let mut direct = prefix.clone();
    for segment in segments {
        if !direct.is_empty() {
            direct.push('.');
        }
        direct.push_str(segment);
    }
    if segments.is_empty() {
        return vec![direct];
    }

    let mut singleton_qualified = prefix;
    if prefix_is_owner {
        singleton_qualified.push('$');
    }
    for (index, segment) in segments.iter().enumerate() {
        if !singleton_qualified.is_empty() {
            singleton_qualified.push('.');
        }
        singleton_qualified.push_str(segment);
        if index + 1 < segments.len() {
            singleton_qualified.push('$');
        }
    }
    if singleton_qualified == direct {
        vec![direct]
    } else {
        vec![direct, singleton_qualified]
    }
}

/// The final `.`-joined segment of a Scala `short_name` (a package-less name
/// that may still carry an owner-chain prefix, e.g. `Outer.inner`). Scala
/// identifiers never contain a literal `.`, so re-tokenizing with the shared
/// structured splitter and taking the last segment reproduces
/// `short_name.rsplit('.').next()`'s terminal-segment split exactly, for any
/// unit kind (function, field, type, or type alias) -- unlike `identifier()`,
/// this never additionally trims a `$` nesting marker.
pub fn scala_short_name_terminal_segment(short_name: &str) -> String {
    brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(Language::Scala, short_name)
        .pop()
        .unwrap_or_else(|| short_name.to_string())
}

/// The bare type name a declaration is spelled with, `$` companion marker
/// trimmed.
pub fn scala_simple_type_name(unit: &CodeUnit) -> String {
    // Reuses the shared terminal-segment splitter (see its doc comment):
    // Scala identifiers never contain a literal `.`, so this reproduces
    // `short_name.rsplit('.').next()`'s terminal split exactly.
    scala_short_name_terminal_segment(unit.short_name())
        .trim_end_matches('$')
        .to_string()
}

/// The declared return type of a Scala member signature, if it spells one.
pub fn scala_signature_return_type(signature: &str) -> Option<&str> {
    let (_, after_colon) = signature.rsplit_once(':')?;
    let end = after_colon.find(['=', '{']).unwrap_or(after_colon.len());
    let return_type = after_colon[..end].trim();
    (!return_type.is_empty()).then_some(return_type)
}

/// The parameter count a Scala member signature declares, extension methods
/// counted after their receiver clause.
pub fn scala_member_signature_arity(signature: &str) -> Option<usize> {
    if let Some(extension_signature) = signature.strip_prefix("extension ") {
        let after_receiver = extension_signature.split_once(')')?.1.trim_start();
        return after_receiver
            .find('(')
            .and_then(|open| scala_parenthesized_arity(&after_receiver[open..]))
            .or(Some(0));
    }
    let open = signature.find('(')?;
    scala_parenthesized_arity(&signature[open..])
}

/// The contents of the balanced parenthesized group `source` opens with.
pub fn scala_balanced_parenthesized_prefix(source: &str) -> Option<&str> {
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

/// Split `value` on the commas that sit outside every bracket group.
pub fn scala_split_top_level_commas(value: &str) -> impl Iterator<Item = &str> {
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

/// The number of top-level entries in the parenthesized group `source` opens
/// with.
pub fn scala_parenthesized_arity(source: &str) -> Option<usize> {
    let inner = scala_balanced_parenthesized_prefix(source)?;
    if inner.trim().is_empty() {
        return Some(0);
    }
    Some(scala_split_top_level_commas(inner).count())
}
/// Whether `name` is a type the Scala standard prelude puts in scope without
/// an import.
///
/// The list is deliberately generous: every entry is a name the analyzer will
/// never find a workspace declaration for, so a semantic diagnostic that
/// reported it would be a guaranteed false positive.
pub fn scala_default_type_name(name: &str) -> bool {
    if scala_standard_arity_type_name(name) {
        return true;
    }
    matches!(
        name,
        "Any"
            | "AnyRef"
            | "AnyVal"
            | "Nothing"
            | "Null"
            | "Unit"
            | "Boolean"
            | "Byte"
            | "Short"
            | "Int"
            | "Long"
            | "Float"
            | "Double"
            | "Char"
            | "String"
            | "Array"
            | "Option"
            | "Some"
            | "None"
            | "Either"
            | "Left"
            | "Right"
            | "List"
            | "Nil"
            | "Seq"
            | "Set"
            | "Map"
            | "Iterable"
            | "Iterator"
            | "Product"
            | "PartialFunction"
            | "Matchable"
            | "Dynamic"
            | "Singleton"
            | "AnyKind"
            | "CanEqual"
            | "ValueOf"
            | "DummyImplicit"
            | "RuntimeException"
            | "Exception"
            | "Throwable"
            | "Error"
            | "Object"
            | "Class"
            | "Number"
            | "Math"
            | "System"
            | "StringBuilder"
    )
}

/// The arity-suffixed prelude families -- `TupleN`, `FunctionN`,
/// `ContextFunctionN` for N up to 22.
pub fn scala_standard_arity_type_name(name: &str) -> bool {
    for prefix in ["Tuple", "Function", "ContextFunction"] {
        if let Some(arity) = name
            .strip_prefix(prefix)
            .and_then(|value| value.parse::<u8>().ok())
            && arity <= 22
        {
            return true;
        }
    }
    false
}
