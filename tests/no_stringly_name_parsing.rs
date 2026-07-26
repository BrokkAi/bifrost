//! Guard test (ExecPlan `fqname-interned-segments.md`, M4): the analyzer must not
//! re-infer qualified-name *structure* by splitting a name string on a delimiter.
//!
//! Bifrost historically identified every declaration by a plain string
//! (`package_name` + `short_name` on `CodeUnit`) and every consumer re-inferred
//! where one segment ended and the next began by splitting on a guessed set of
//! delimiters. That inference was a recurring bug factory (issues #1126, #1128,
//! #1162, #1163). The `FqName` representation records the structure once, at
//! construction, so the split-based re-inference must not creep back in.
//!
//! This gate walks `src/analyzer/**/*.rs` and fails on three name-parsing
//! shapes — the exact bug surface the plan set out to kill:
//!
//!   A. Splitting the result of a `CodeUnit` name accessor
//!      (`.short_name()` / `.package_name()` / `.fq_name()`) on a separator to
//!      recover owner/member structure. The unit already carries a structured
//!      `fq()`; pop/walk its segments instead of re-splitting the rendered string.
//!
//!   B. Splitting any string on the `$` separator. `$` is used *only* as a
//!      name-nesting boundary in this tree (Scala companion objects, and the
//!      `$`-joined nested types of python/php/ruby/cpp/java). A `$` split is
//!      therefore always name-structure re-inference — the precise shape that
//!      collided with rust raw identifiers (`r#type`) in #1128 and with Scala's
//!      `$` spelling in #1126.
//!
//!   C. Shape A spread across more than one source line instead of chained on
//!      one: either the method chain continues onto a following line
//!      (rustfmt's usual style once a chain is too long for one line, e.g.
//!      `target\n    .short_name()\n    .split('.')`), or the accessor's
//!      result is first bound to a local variable that is split later
//!      (`let short = target.short_name(); ... short.split('.')`). Both are
//!      Shape A's exact re-inference bug; only the source formatting differs,
//!      and the M4/batch-1/batch-2 census's per-line Shape A matcher could not
//!      see either (two real instances were found this way in
//!      `src/analyzer/common.rs` and `src/analyzer/scala/mod.rs` during
//!      issue #1168's batch 2 and fixed in batch 3 — see the ExecPlan's
//!      Outcomes for the census).
//!
//! The gate deliberately does NOT ban the general `.split('.')` / `.split("::")`
//! family: those overwhelmingly parse *source syntax* — call-target text,
//! signatures, import paths, module specifiers read straight off the AST — which
//! is legitimate, structured, source-derived parsing (the plan bans replacing the
//! tree-sitter AST with string scanning, not parsing source tokens). Narrowing to
//! the shapes above keeps the gate precise: a legitimate signature or path split
//! never trips it, so no allowlist entry is needed for the bulk of the tree.
//!
//! A line that genuinely must keep one of these shapes — a structured best-effort
//! on a name string where the `FqName` is not threaded to that surface yet, or a
//! sanctioned interning/rendering boundary — is exempted by an inline
//! `// fqname-M4:` comment on the same line, stating the reason. Introduce a NEW
//! banned split without that comment and this test fails the build. For shape C,
//! the comment may sit on the matched (split) line, on the line carrying the
//! accessor call, or anywhere in the contiguous `//`-comment block directly
//! above either — the exemption walk tolerates chain-continuation lines
//! (trimmed text starting with `.`) between the split line and the comment, so
//! a reason written once above a multi-line chain or above a `let` binding
//! covers the whole statement.
//!
//! Verify the gate bites (mutation check, run once): add
//! `let _ = some_unit.short_name().rsplit_once('$');` (no `// fqname-M4:`
//! comment) to any `src/analyzer` file and run this test — it fails, naming the
//! file and line; remove it and it passes again. Shape C was verified the same
//! way with a multi-line chain and a let-binding mutation (see the ExecPlan).

use std::path::{Path, PathBuf};

/// Inline exemption token. A line carrying this (in a trailing comment) is a
/// reviewed, deliberately-retained occurrence; the comment text states why.
const ALLOW_TOKEN: &str = "fqname-M4";

/// Split-family method names that, applied to a name string, re-infer structure.
const SPLIT_METHODS: &[&str] = &[
    "split",
    "rsplit",
    "splitn",
    "rsplitn",
    "split_once",
    "rsplit_once",
    "rfind",
];

/// `CodeUnit` name accessors whose rendered-string result must not be
/// re-split to recover structure (shapes A and C).
const ACCESSORS: &[&str] = &[".short_name()", ".package_name()", ".fq_name()"];

fn analyzer_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/analyzer")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Shape A: a `CodeUnit` name accessor immediately followed by a split-family
/// call on the same line, e.g. `target.short_name().rsplit_once('.')`.
fn matches_accessor_split(line: &str) -> bool {
    for accessor in ACCESSORS {
        let mut from = 0;
        while let Some(pos) = line[from..].find(accessor) {
            let after = &line[from + pos + accessor.len()..];
            let after = after.trim_start();
            if let Some(rest) = after.strip_prefix('.') {
                let rest = rest.trim_start();
                if SPLIT_METHODS
                    .iter()
                    .any(|m| rest.starts_with(&format!("{m}(")))
                {
                    return true;
                }
            }
            from += pos + accessor.len();
        }
    }
    false
}

/// Shape B: a split-family call whose separator literal contains `$`, e.g.
/// `name.rsplit('$')`, `s.split("$")`, or `x.rsplit(['.', '$'])`.
fn matches_dollar_split(line: &str) -> bool {
    for method in SPLIT_METHODS {
        let needle = format!(".{method}(");
        let mut from = 0;
        while let Some(pos) = line[from..].find(&needle) {
            let start = from + pos + needle.len();
            // Inspect the argument list up to the matching close paren (single
            // line; a `$` inside a `'..'`/".." literal here is a name separator).
            let arg = &line[start..];
            if let Some(end) = arg.find(')') {
                let arg = &arg[..end];
                if arg.contains("'$'") || arg.contains("\"$\"") || arg.contains("'$'") {
                    return true;
                }
                // char-class array form: ['.', '$'] etc.
                if arg.contains('$') && (arg.contains('\'') || arg.contains('"')) {
                    return true;
                }
            }
            from = start;
        }
    }
    false
}

/// A rustfmt-style method-chain continuation line: the trimmed text starts
/// with `.` (the receiver/earlier calls are on prior lines).
fn is_continuation_line(trimmed: &str) -> bool {
    trimmed.starts_with('.')
}

/// Extracts `IDENT` from a bare `let IDENT = ..` / `let mut IDENT = ..` /
/// `let IDENT: Type = ..` binding at the start of `line`, or `None` if `line`
/// is not such a binding (in particular, destructuring patterns like
/// `let (a, b) = ..` or `let Some(x) = ..` are not bindings this scanner can
/// safely track and are skipped).
fn let_binding_identifier(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix("let ")?;
    let rest = rest.strip_prefix("mut ").unwrap_or(rest).trim_start();
    let ident_len = rest
        .find(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
        .unwrap_or(rest.len());
    let ident = &rest[..ident_len];
    if ident.is_empty() {
        return None;
    }
    let after = rest[ident_len..].trim_start();
    if after.starts_with('=') || after.starts_with(':') {
        Some(ident.to_string())
    } else {
        None
    }
}

/// Whether `line` uses `ident` as the receiver of a split-family call
/// (`ident.split(..)`, `ident.rsplit_once(..)`, etc.), guarding against a
/// longer identifier merely containing `ident` as a substring (checks the
/// character immediately before the match is not itself an identifier
/// character).
fn uses_identifier_as_split_receiver(line: &str, ident: &str) -> bool {
    let needle = format!("{ident}.");
    let mut from = 0;
    while let Some(pos) = line[from..].find(&needle) {
        let start = from + pos;
        let preceded_by_ident_char = start > 0
            && line[..start]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_alphanumeric() || ch == '_');
        if !preceded_by_ident_char {
            let after = &line[start + needle.len()..];
            if SPLIT_METHODS
                .iter()
                .any(|m| after.starts_with(&format!("{m}(")))
            {
                return true;
            }
        }
        from = start + needle.len();
    }
    false
}

/// Walks a `.`-prefixed method-chain continuation backward from `line_index`
/// to the line that starts the chain (the receiver expression, or a line
/// that is not itself a continuation). Used to find where a multi-line chain
/// — and therefore its exemption comment, if any — begins.
fn chain_start_line(lines: &[&str], mut line_index: usize) -> usize {
    while line_index > 0 && is_continuation_line(lines[line_index].trim_start()) {
        line_index -= 1;
    }
    line_index
}

/// Shape C: a `CodeUnit` name accessor's result reaching a split-family call
/// without both appearing on the same source line. Two sub-shapes, both
/// exactly Shape A's re-inference bug spread across lines instead of chained
/// on one:
///
///   (i) a direct method-chain continuation — the accessor call is on one
///       line and a split-family call is chained on a later, `.`-prefixed
///       continuation line, with nothing but continuation lines between them;
///
///   (ii) a local-variable binding — `let IDENT = <expr containing an
///        accessor call>;` (possibly itself spanning continuation lines),
///        followed later in the same enclosing block by `IDENT.<split-family
///        call>`.
///
/// Returns, for each hit, the 0-based line index of the split-family call
/// (where the violation is reported, mirroring shapes A/B) paired with the
/// 0-based line index where its statement begins (where an exemption comment
/// above the statement should be looked for — see [`is_exempted`]).
fn find_shape_c_violations(lines: &[&str]) -> Vec<(usize, usize)> {
    let mut hits: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();

    // (i) direct multi-line chain.
    for (index, line) in lines.iter().enumerate() {
        if matches_accessor_split(line) {
            // Same-line Shape A already covers this line; avoid double-
            // reporting it as shape C too.
            continue;
        }
        if !ACCESSORS.iter().any(|accessor| line.contains(accessor)) {
            continue;
        }
        let mut probe = index + 1;
        while probe < lines.len() {
            let candidate = lines[probe].trim_start();
            if !is_continuation_line(candidate) {
                break;
            }
            if SPLIT_METHODS
                .iter()
                .any(|m| candidate.starts_with(&format!(".{m}(")))
            {
                let start = chain_start_line(lines, index);
                hits.entry(probe)
                    .and_modify(|s| *s = (*s).min(start))
                    .or_insert(start);
                break;
            }
            probe += 1;
        }
    }

    // (ii) local-variable binding, split later in the same enclosing block.
    for (index, line) in lines.iter().enumerate() {
        let Some(ident) = let_binding_identifier(line) else {
            continue;
        };
        // Gather the statement text (this line plus any continuation lines)
        // up to its terminating `;`, bounded to a small span so a missing
        // `;` cannot make this scan unbounded.
        let mut statement = line.to_string();
        let mut end = index;
        if !line.trim_end().ends_with(';') {
            let limit = lines.len().min(index + 16);
            for (probe, text) in lines.iter().enumerate().take(limit).skip(index + 1) {
                statement.push('\n');
                statement.push_str(text);
                end = probe;
                if text.trim_end().ends_with(';') {
                    break;
                }
            }
        }
        if !ACCESSORS
            .iter()
            .any(|accessor| statement.contains(accessor))
        {
            continue;
        }
        // Search forward through the enclosing block only: stop once a `}`
        // closes past the binding's own nesting depth. Pure comment lines
        // are skipped entirely (a doc comment mentioning `ident.split(..)`
        // as prose must not count as a use).
        let mut depth = 0i32;
        for (probe, text) in lines.iter().enumerate().skip(end + 1) {
            let text = *text;
            if text.trim_start().starts_with("//") {
                continue;
            }
            if uses_identifier_as_split_receiver(text, &ident) {
                hits.entry(probe)
                    .and_modify(|s| *s = (*s).min(index))
                    .or_insert(index);
                break;
            }
            let mut exited = false;
            for ch in text.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth < 0 {
                            exited = true;
                        }
                    }
                    _ => {}
                }
            }
            if exited {
                break;
            }
        }
    }

    hits.into_iter().collect()
}

/// Whether the split-family call at `hit_index` (0-based), whose enclosing
/// statement begins at `statement_start` (0-based; equal to `hit_index` for
/// shapes A/B, which are always single-line), carries or is covered by a
/// `// fqname-M4:` exemption comment. The comment may sit anywhere in the
/// statement itself (the matched line, or an earlier line of a multi-line
/// chain/binding), or in the contiguous block of `//` comment lines directly
/// above the statement's first line.
fn is_exempted(lines: &[&str], hit_index: usize, statement_start: usize) -> bool {
    if (statement_start..=hit_index).any(|i| lines[i].contains(ALLOW_TOKEN)) {
        return true;
    }
    let mut above = statement_start;
    while above > 0 {
        let prev = lines[above - 1].trim_start();
        if !prev.starts_with("//") {
            break;
        }
        if prev.contains(ALLOW_TOKEN) {
            return true;
        }
        above -= 1;
    }
    false
}

#[test]
fn analyzer_does_not_reinfer_name_structure_by_splitting() {
    let root = analyzer_root();
    let mut files = Vec::new();
    rust_sources(&root, &mut files);
    assert!(
        files.len() > 100,
        "expected to walk the analyzer tree, found only {} files",
        files.len()
    );

    // The gate must be exercising itself against real code: prove it sees the
    // known population (the shapes exist and are all exempted today).
    let mut exempted = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        let shape_c_hits: std::collections::BTreeMap<usize, usize> =
            find_shape_c_violations(&lines).into_iter().collect();
        for (index, line) in lines.iter().enumerate() {
            let statement_start = if matches_accessor_split(line) || matches_dollar_split(line) {
                Some(index)
            } else {
                shape_c_hits.get(&index).copied()
            };
            let Some(statement_start) = statement_start else {
                continue;
            };
            let rel = file.strip_prefix(&root).unwrap_or(file).display();
            if is_exempted(&lines, index, statement_start) {
                exempted += 1;
                continue;
            }
            violations.push(format!(
                "  src/analyzer/{rel}:{}: {}",
                index + 1,
                line.trim()
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "found {} name-structure split(s) re-inferring qualified-name structure by \
         string splitting (ExecPlan fqname-interned-segments.md, M4). Pop/walk the \
         unit's structured `fq()` segments instead, or — if the FqName is genuinely \
         not threaded to that surface yet — add a trailing `// {ALLOW_TOKEN}: <reason>` \
         comment explaining why. Offending lines:\n{}",
        violations.len(),
        violations.join("\n")
    );

    // Drift guard: the shapes exist in the tree today (all exempted with a
    // reason). If the matchers ever stop seeing them, their patterns have drifted
    // and the gate is silently guarding nothing.
    assert!(
        exempted > 0,
        "the gate matched no known name-parsing shapes — its patterns have drifted \
         and it is no longer guarding anything"
    );
}

#[cfg(test)]
mod shape_c_unit_tests {
    use super::*;

    #[test]
    fn detects_multi_line_chain_continuation() {
        let source = "fn f(target: &CodeUnit) -> bool {\n    target\n        .short_name()\n        .split('.')\n        .any(|s| s.is_empty())\n}\n";
        let lines: Vec<&str> = source.lines().collect();
        let hits = find_shape_c_violations(&lines);
        assert_eq!(
            hits,
            vec![(3, 1)],
            "expected the `.split('.')` continuation line (3) to be flagged, statement \
             starting at the `target` receiver line (1)"
        );
    }

    #[test]
    fn detects_let_bound_accessor_split_later() {
        let source = "fn f(target: &CodeUnit) -> Option<String> {\n    let short = target.short_name();\n    let simple = short.rsplit('.').next()?;\n    Some(simple.to_string())\n}\n";
        let lines: Vec<&str> = source.lines().collect();
        let hits = find_shape_c_violations(&lines);
        assert_eq!(
            hits,
            vec![(2, 1)],
            "expected the `short.rsplit('.')` line (2) to be flagged, statement starting \
             at the `let short = ..` binding line (1)"
        );
    }

    #[test]
    fn exemption_comment_above_chain_covers_whole_statement() {
        let source = "fn f(target: &CodeUnit) -> bool {\n    // fqname-M4: test exemption above a multi-line chain\n    target\n        .short_name()\n        .split('.')\n        .any(|s| s.is_empty())\n}\n";
        let lines: Vec<&str> = source.lines().collect();
        let hits = find_shape_c_violations(&lines);
        assert_eq!(hits.len(), 1);
        let (hit, start) = hits[0];
        assert!(is_exempted(&lines, hit, start));
    }

    #[test]
    fn exemption_comment_above_let_binding_covers_later_split() {
        let source = "fn f(target: &CodeUnit) -> Option<String> {\n    // fqname-M4: test exemption above a let-bound accessor\n    let short = target.short_name();\n    let simple = short.rsplit('.').next()?;\n    Some(simple.to_string())\n}\n";
        let lines: Vec<&str> = source.lines().collect();
        let hits = find_shape_c_violations(&lines);
        assert_eq!(hits.len(), 1);
        let (hit, start) = hits[0];
        assert!(is_exempted(&lines, hit, start));
    }

    #[test]
    fn does_not_flag_unrelated_split_after_unrelated_binding() {
        let source = "fn f(path: &str) -> Vec<&str> {\n    let parts = path;\n    parts.split('/').collect()\n}\n";
        let lines: Vec<&str> = source.lines().collect();
        assert!(find_shape_c_violations(&lines).is_empty());
    }

    #[test]
    fn does_not_flag_split_mentioned_only_in_a_comment() {
        let source = "fn f(target: &CodeUnit) -> Option<String> {\n    let fqn = target.fq_name();\n    // prose mentioning `fqn.rsplit_once('.')` as documentation, not code\n    Some(fqn)\n}\n";
        let lines: Vec<&str> = source.lines().collect();
        assert!(find_shape_c_violations(&lines).is_empty());
    }
}
