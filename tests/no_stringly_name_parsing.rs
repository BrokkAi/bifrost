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
//! This gate walks `src/analyzer/**/*.rs` and fails on the two sharpest
//! name-parsing shapes — the exact bug surface the plan set out to kill:
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
//! The gate deliberately does NOT ban the general `.split('.')` / `.split("::")`
//! family: those overwhelmingly parse *source syntax* — call-target text,
//! signatures, import paths, module specifiers read straight off the AST — which
//! is legitimate, structured, source-derived parsing (the plan bans replacing the
//! tree-sitter AST with string scanning, not parsing source tokens). Narrowing to
//! the two shapes above keeps the gate precise: a legitimate signature or path
//! split never trips it, so no allowlist entry is needed for the bulk of the tree.
//!
//! A line that genuinely must keep one of these shapes — a structured best-effort
//! on a name string where the `FqName` is not threaded to that surface yet, or a
//! sanctioned interning/rendering boundary — is exempted by an inline
//! `// fqname-M4:` comment on the same line, stating the reason. Introduce a NEW
//! banned split without that comment and this test fails the build.
//!
//! Verify the gate bites (mutation check, run once): add
//! `let _ = some_unit.short_name().rsplit_once('$');` (no `// fqname-M4:`
//! comment) to any `src/analyzer` file and run this test — it fails, naming the
//! file and line; remove it and it passes again.

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
    const ACCESSORS: &[&str] = &[".short_name()", ".package_name()", ".fq_name()"];
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
    // known population (the two shapes exist and are all exempted today).
    let mut exempted = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let is_banned = matches_accessor_split(line) || matches_dollar_split(line);
            if !is_banned {
                continue;
            }
            let rel = file.strip_prefix(&root).unwrap_or(file).display();
            // The exemption comment may sit on the matched line, or anywhere in
            // the contiguous block of `//` comment lines immediately above it
            // (Rust chains a split onto its own line, so the reason is written on
            // the preceding line[s] of the chain, possibly spanning several).
            let mut exempted_here = line.contains(ALLOW_TOKEN);
            let mut above = index;
            while !exempted_here && above > 0 {
                let prev = lines[above - 1].trim_start();
                if !prev.starts_with("//") {
                    break;
                }
                exempted_here = prev.contains(ALLOW_TOKEN);
                above -= 1;
            }
            if exempted_here {
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

    // Drift guard: the two shapes exist in the tree today (all exempted with a
    // reason). If the matchers ever stop seeing them, their patterns have drifted
    // and the gate is silently guarding nothing.
    assert!(
        exempted > 0,
        "the gate matched no known name-parsing shapes — its patterns have drifted \
         and it is no longer guarding anything"
    );
}
