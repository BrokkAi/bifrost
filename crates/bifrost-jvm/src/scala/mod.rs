//! Scala language knowledge.

pub mod adapter;
pub mod clones;
pub mod declarations;
pub mod graph;
pub mod imports;
pub mod language;
pub mod structural;
pub mod supertypes;
pub mod test_detection;
pub mod wildcard_imports;

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
