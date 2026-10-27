//! Workspace-relative path normalization shared by every Bifrost surface.
//!
//! The analyzer-facing resolver that turns a caller-supplied literal into a
//! [`ProjectFile`] lives in `brokk-bifrost-analysis` instead: it reads a
//! workspace listing off an `IAnalyzer`, which is above this crate.

use std::borrow::Cow;
use std::path::{Component, Path, PathBuf};

use crate::analyzer::ProjectFile;

pub fn normalize_pattern(pattern: &str) -> String {
    pattern.replace('\\', "/")
}

/// Whether `pattern` contains any supported glob metacharacter.
pub fn contains_glob_syntax(pattern: &str) -> bool {
    pattern.contains(['*', '?', '['])
}

pub fn rel_path_string(file: &ProjectFile) -> String {
    file.rel_path().to_string_lossy().replace('\\', "/")
}

/// Whether `path` starts with a Windows drive-absolute prefix.
pub fn is_windows_absolute_path(path: &str) -> bool {
    has_drive_letter_prefix(path) && matches!(path.as_bytes().get(2), Some(b'/' | b'\\'))
}

/// Render a workspace-relative path as a slash-separated key by joining its
/// path components. A backslash that is part of a Unix filename stays literal.
pub fn workspace_relative_slash_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// The path-suffix key `path` denotes: its `Normal` components joined with
/// `/`, or `None` when it has none.
///
/// This is the spelling both halves of the tier demand record (#1865) agree on.
/// A demand key is recorded from the target text of an import directive that
/// resolved to nothing, and a candidate file is tested by generating
/// [`path_suffix_keys`] of its workspace-relative path: a hit means the file
/// could satisfy that directive.
///
/// Non-`Normal` components (`.`, `..`, a root, a Windows prefix) are dropped
/// rather than rejected, which widens the key -- `../gen/x.inc` records
/// `gen/x.inc`. Widening is the safe direction: the demand record decides
/// whether to *re-derive*, so an over-broad key costs one derivation and a
/// too-narrow one would silently drop a file from the index.
pub fn path_suffix_key(path: &Path) -> Option<String> {
    let mut key = String::new();
    for part in normal_path_components(path) {
        if !key.is_empty() {
            key.push('/');
        }
        key.push_str(&part);
    }
    (!key.is_empty()).then_some(key)
}

fn normal_path_components(path: &Path) -> impl Iterator<Item = Cow<'_, str>> {
    path.components().filter_map(|component| match component {
        Component::Normal(part) => Some(part.to_string_lossy()),
        _ => None,
    })
}

/// Every suffix of `path`'s `Normal` components as a [`path_suffix_key`],
/// longest first: `a/b/c.inc` yields `a/b/c.inc`, `b/c.inc`, `c.inc`.
///
/// A recorded demand key matches `path` exactly when it is one of these, which
/// is the same relation `#include` resolution uses -- full workspace-relative
/// path, includer-relative path, and the trailing-components fallback are all
/// component suffixes of the file that satisfies them.
pub fn path_suffix_keys(path: &Path) -> Vec<String> {
    let parts: Vec<String> = normal_path_components(path)
        .map(|part| part.into_owned())
        .collect();
    (0..parts.len())
        .map(|start| parts[start..].join("/"))
        .collect()
}

// Reject absolute paths, root-anchored paths, and Windows drive-relative
// references so MCP callers cannot escape the active workspace via a crafted
// `file_paths` entry. Returns the normalized project-relative path on success.
//
// The drive-letter test runs on every component, not only on the head of the
// input. `PathBuf::push` replaces the whole buffer when the pushed segment
// carries a prefix but no root, so a drive-shaped segment is a workspace escape
// wherever it sits: on Windows `./C:/x` would otherwise accumulate to the
// drive-relative `C:x`, and `workspace_root.join("C:x")` resolves against drive
// C's current directory rather than the workspace. A head-only test also left
// the accepted form outside the function's own domain -- `./a:` was accepted as
// `a:`, which the head test then rejected -- so per-component rejection is what
// makes an accepted path a fixed point.
pub fn workspace_rel_path(input: &str) -> Option<PathBuf> {
    let normalized = normalize_pattern(input);
    let trimmed = normalized.trim_start_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let path = Path::new(trimmed);
    if path.is_absolute() || path.has_root() {
        return None;
    }
    let mut rel = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => {
                if has_drive_letter_prefix(&part.to_string_lossy()) {
                    return None;
                }
                rel.push(part);
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if rel.as_os_str().is_empty() {
        return None;
    }
    Some(rel)
}

/// Normalize `path` against a relative base, rejecting attempts to escape it.
pub fn normalize_relative_path_from(base: &Path, path: &Path) -> Option<PathBuf> {
    let mut normalized = base.to_path_buf();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                normalized.pop().then_some(())?;
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

pub fn has_drive_letter_prefix(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some(c1), Some(':')) if c1.is_ascii_alphabetic()
    )
}

pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            out.push((high << 4) | low);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        contains_glob_syntax, is_windows_absolute_path, normalize_relative_path_from,
        percent_decode, workspace_rel_path, workspace_relative_slash_path,
    };
    use std::path::{Path, PathBuf};

    /// The spellings that decide a rev:path split (`C:\x` is a path, not rev
    /// `C`) and a workspace-escape check: only a drive letter, a colon, and a
    /// separator make a drive-absolute path.
    #[test]
    fn is_windows_absolute_path_distinguishes_windows_path_forms() {
        for absolute in ["C:\\", "C:/", "c:\\dir\\f.rs", "Z:/dir/f.rs", "C:\\a:b"] {
            assert!(is_windows_absolute_path(absolute), "rejected {absolute:?}");
        }
        for other in [
            "",
            "C",
            "C:",
            "C:foo",
            "C:foo\\bar",
            "\\\\server\\share\\f.rs",
            "//server/share/f.rs",
            "\\\\?\\C:\\f.rs",
            "/C:/f.rs",
            "./C:/f.rs",
            "1:/f.rs",
            "src/main.rs",
        ] {
            assert!(!is_windows_absolute_path(other), "accepted {other:?}");
        }
    }

    #[test]
    fn contains_glob_syntax_recognizes_each_metacharacter() {
        for glob in ["*", "src/**/*.rs", "a?c", "[ab]", "dir/[", "trail*"] {
            assert!(contains_glob_syntax(glob), "missed {glob:?}");
        }
        for literal in [
            "",
            "src/main.rs",
            "a{b,c}",
            "a!b",
            "dir\\file",
            "na\u{ef}ve",
        ] {
            assert!(!contains_glob_syntax(literal), "flagged {literal:?}");
        }
    }

    /// Climbing above the base is the escape the function exists to reject,
    /// but climbing back down to the base itself is allowed.
    #[test]
    fn normalize_relative_path_from_rejects_escape_and_anchors() {
        let base = Path::new("a/b");
        assert_eq!(
            normalize_relative_path_from(base, Path::new("../c")),
            Some(PathBuf::from("a").join("c")),
        );
        assert_eq!(
            normalize_relative_path_from(base, Path::new("../..")),
            Some(PathBuf::new()),
        );
        assert_eq!(
            normalize_relative_path_from(base, Path::new("../../..")),
            None
        );
        assert_eq!(normalize_relative_path_from(base, Path::new("/abs")), None);
        assert_eq!(
            normalize_relative_path_from(Path::new(""), Path::new("./x/./y")),
            Some(PathBuf::from("x").join("y")),
        );
    }

    #[test]
    fn workspace_relative_slash_path_joins_components() {
        let path = Path::new("src").join("main.rs");
        assert_eq!("src/main.rs", workspace_relative_slash_path(&path));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_relative_slash_path_preserves_literal_unix_backslash() {
        assert_eq!(
            r"literal\backslash.rs",
            workspace_relative_slash_path(Path::new(r"literal\backslash.rs")),
        );
    }

    #[test]
    fn percent_decode_handles_unicode_spaces_and_malformed_escapes() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%E2%9C%93"), "✓");
        assert_eq!(percent_decode("plain/path"), "plain/path");
        assert_eq!(percent_decode("incomplete%2"), "incomplete%2");
        assert_eq!(percent_decode("invalid%XZ"), "invalid%XZ");
    }

    /// A drive-shaped segment is rejected wherever it sits, not only at the
    /// head of the input. On Windows `PathBuf::push` replaces the accumulated
    /// buffer for such a segment, so `./C:/x` would otherwise be accepted as
    /// the drive-relative `C:x` and `workspace_root.join("C:x")` would resolve
    /// against drive C's current directory instead of the workspace. The
    /// leading `?` case is what a verbatim UNC spelling normalizes to after the
    /// root trim.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "92139ed3d8b9: a drive-shaped component inside the path could escape the workspace"
    )]
    fn workspace_rel_path_rejects_drive_shaped_components_anywhere() {
        for input in [
            "C:/x", "./C:/x", "a/C:/b", "a\\C:\\b", "./a:", "a:", "a/b:", "?/C:/x",
        ] {
            assert_eq!(workspace_rel_path(input), None, "accepted {input:?}");
        }
        assert_eq!(
            workspace_rel_path("./src/main.rs"),
            Some(PathBuf::from("src").join("main.rs")),
        );
    }
}

/// Generative tests for the workspace-relative path contract.
///
/// The bug class these guard is a path string that was interpreted by hand
/// instead of by the structured type: a `rev:path` split on `:` that ate a
/// Windows drive letter (8b0bd1e94), an evidence-row parse that rejected every
/// Windows path (4565dc3c0), and the workspace-escape hardening that says no
/// accepted path may leave the workspace root (a6bff4d37). Each property below
/// pins one function's contract as written in this file, so a future rewrite
/// that drifts from it fails here rather than at an MCP boundary.
#[cfg(test)]
mod path_properties {
    use std::path::{Component, Path, PathBuf};

    use proptest::prelude::*;

    use super::{
        contains_glob_syntax, has_drive_letter_prefix, is_windows_absolute_path, normalize_pattern,
        normalize_relative_path_from, path_suffix_key, path_suffix_keys, percent_decode,
        rel_path_string, workspace_rel_path,
    };
    use crate::analyzer::ProjectFile;

    fn literal(value: &str) -> Just<String> {
        Just(value.to_string())
    }

    /// Percent-encodes every byte of `input`'s UTF-8 form as `%XX`.
    ///
    /// This is deliberately the maximal encoder rather than a URL-correct one:
    /// it is a total injection into the escape alphabet, so `percent_decode`
    /// must invert it for every string.
    fn percent_encode_all(input: &str) -> String {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut out = String::with_capacity(input.len() * 3);
        for &byte in input.as_bytes() {
            out.push('%');
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        out
    }

    /// One path segment, biased toward the shapes that break hand-rolled path
    /// parsers: dot segments, drive-letter lookalikes, percent escapes, and
    /// non-ASCII.
    fn path_token() -> impl Strategy<Value = String> {
        prop_oneof![
            "[a-z]{1,3}",
            literal(""),
            literal("."),
            literal(".."),
            "[A-Za-z]:",
            literal("1:"),
            literal("a;"),
            literal("%2e%2e"),
            prop_oneof![
                literal("%"),
                literal("%z"),
                literal("%41"),
                literal("%FF%FE"),
            ],
            prop_oneof![
                literal("na\u{ef}ve"),
                literal("with space"),
                literal("~"),
                "[A-Za-z0-9_.%-]{0,4}",
            ],
        ]
    }

    /// A separator run: both separators, doubled and mixed.
    fn separator_token() -> impl Strategy<Value = String> {
        prop_oneof![
            literal("/"),
            literal("\\"),
            literal("//"),
            literal("\\\\"),
            literal("/\\"),
        ]
    }

    /// A leading anchor: roots, dot prefixes, drive letters, and UNC shapes.
    fn prefix_token() -> impl Strategy<Value = String> {
        prop_oneof![
            literal(""),
            literal("/"),
            literal("//"),
            literal("\\"),
            literal("\\\\"),
            literal("/C:/"),
            literal("\\\\server\\share\\"),
            literal("\\\\?\\C:\\"),
            prop_oneof![
                literal("./"),
                literal(".\\"),
                literal("../"),
                literal("..\\"),
            ],
            prop_oneof![
                literal("C:\\"),
                literal("c:/"),
                literal("C:"),
                literal("C:/"),
            ],
        ]
    }

    /// An adversarial path string: anchor, then segments joined by separator
    /// runs, with an optional trailing separator.
    fn adversarial_path() -> impl Strategy<Value = String> {
        (
            prefix_token(),
            prop::collection::vec((path_token(), separator_token()), 1..5),
            any::<bool>(),
        )
            .prop_map(|(prefix, parts, trailing)| {
                let last = parts.len() - 1;
                let mut out = prefix;
                for (index, (token, separator)) in parts.into_iter().enumerate() {
                    out.push_str(&token);
                    if index < last || trailing {
                        out.push_str(&separator);
                    }
                }
                out
            })
    }

    /// A segment that survives `Path::components` as a single `Normal`: it
    /// starts with a letter, so it is never `.`, `..`, empty, or a separator.
    fn safe_component() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_.-]{0,4}"
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// `normalize_pattern` maps `\` to `/` and nothing else, so it removes
        /// every backslash, is idempotent, and preserves the character count.
        #[test]
        fn normalize_pattern_is_total_and_idempotent(
            input in prop_oneof![adversarial_path(), any::<String>()],
        ) {
            let once = normalize_pattern(&input);
            prop_assert!(!once.contains('\\'), "backslash survived in {once:?}");
            prop_assert_eq!(normalize_pattern(&once), once.clone());
            prop_assert_eq!(once.chars().count(), input.chars().count());
            prop_assert_eq!(
                once.chars().filter(|c| *c == '/').count(),
                input.chars().filter(|c| *c == '/' || *c == '\\').count(),
            );
        }



        /// The documented rejections. Note the leading-`/` trim happens first,
        /// so a root anchor is stripped rather than rejected; everything the
        /// trimmed string still spells as a parent, root, prefix, or nothing at
        /// all must yield `None`.
        #[test]
        fn workspace_rel_path_rejects_escapes(input in adversarial_path()) {
            let trimmed = normalize_pattern(&input).trim_start_matches('/').to_string();
            let result = workspace_rel_path(&input);

            if trimmed.is_empty() {
                prop_assert!(result.is_none(), "empty input accepted: {input:?}");
            }
            if has_drive_letter_prefix(&trimmed) {
                prop_assert!(result.is_none(), "drive-relative accepted: {input:?}");
            }
            if trimmed.split('/').any(|segment| segment == "..") {
                prop_assert!(result.is_none(), "parent segment accepted: {input:?}");
            }
            let non_normal = Path::new(&trimmed)
                .components()
                .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir));
            if non_normal {
                prop_assert!(result.is_none(), "non-normal component accepted: {input:?}");
            }
        }

        /// The accept direction: every spelling of the same benign relative
        /// path -- either separator, doubled separators, a `./` anchor, a
        /// leading root, a trailing separator -- normalizes to one `PathBuf`,
        /// and that `PathBuf` is a fixed point.
        ///
        /// This also keeps the rejection properties honest: without it a
        /// generator that only ever produced rejected input would still pass.
        #[test]
        fn workspace_rel_path_accepts_every_spelling_of_a_benign_path(
            components in prop::collection::vec(safe_component(), 1..6),
        ) {
            let expected: PathBuf = components.iter().collect();
            let spellings = [
                components.join("/"),
                components.join("\\"),
                components.join("//"),
                format!("./{}", components.join("/")),
                format!("/{}", components.join("/")),
                format!("{}/", components.join("/")),
                format!("\\{}\\", components.join("\\")),
            ];
            for spelling in spellings {
                prop_assert_eq!(
                    workspace_rel_path(&spelling),
                    Some(expected.clone()),
                    "spelling {:?}",
                    spelling,
                );
            }
            let spelled = expected.to_string_lossy().into_owned();
            prop_assert_eq!(workspace_rel_path(&spelled), Some(expected));
        }

        /// The security property: an accepted path is built only from `Normal`
        /// components, so joining it onto any root stays under that root.
        ///
        /// This is what forces the drive-letter test to run per component.
        /// `PathBuf::push` replaces the whole buffer when the pushed segment
        /// carries a drive prefix, so on Windows an input such as `./C:/x`
        /// would accumulate to the drive-relative `C:x` and escape the root.
        #[test]
        fn workspace_rel_path_accepts_only_normal_components(input in adversarial_path()) {
            if let Some(rel) = workspace_rel_path(&input) {
                prop_assert!(!rel.as_os_str().is_empty(), "empty accept for {input:?}");
                prop_assert!(rel.is_relative(), "absolute accept {rel:?} for {input:?}");
                for component in rel.components() {
                    prop_assert!(
                        matches!(component, Component::Normal(_)),
                        "non-normal component {component:?} in {rel:?} from {input:?}",
                    );
                }
                let root = PathBuf::from(if cfg!(windows) { "C:\\ws" } else { "/ws" });
                let joined = root.join(&rel);
                prop_assert!(
                    joined.starts_with(&root),
                    "{joined:?} escaped {root:?} via {input:?}",
                );
            }
        }

        /// Re-feeding an accepted path must yield the same path: the accepted
        /// form is the normal form.
        #[test]
        fn workspace_rel_path_is_idempotent(input in adversarial_path()) {
            if let Some(rel) = workspace_rel_path(&input) {
                let spelled = rel.to_string_lossy().into_owned();
                prop_assert!(
                    !has_drive_letter_prefix(&spelled),
                    "accepted {spelled:?} is drive-relative, from {input:?}",
                );
                prop_assert_eq!(
                    workspace_rel_path(&spelled),
                    Some(rel.clone()),
                    "not idempotent for {:?} -> {:?}",
                    input,
                    rel,
                );
            }
        }





        /// A drive letter, a colon, and either separator spell a Windows
        /// drive-absolute path whatever follows; any other third character, a
        /// non-letter drive, or a missing third character does not. The
        /// oracle is the spelling the generator built, not the predicate.
        #[test]
        fn is_windows_absolute_path_follows_the_spelling(
            drive in "[A-Za-z]",
            separator in prop_oneof![literal("/"), literal("\\")],
            tail in any::<String>(),
            not_separator in any::<char>().prop_filter("separator", |c| *c != '/' && *c != '\\'),
            not_a_drive in "[0-9 ._~-]",
        ) {
            let absolute = format!("{drive}:{separator}{tail}");
            let wrong_separator = format!("{drive}:{not_separator}{tail}");
            let wrong_drive = format!("{not_a_drive}:{separator}{tail}");
            let rooted = format!("{separator}{drive}:{separator}{tail}");
            let bare = format!("{drive}:");
            prop_assert!(is_windows_absolute_path(&absolute), "{absolute:?}");
            prop_assert!(!is_windows_absolute_path(&wrong_separator), "{wrong_separator:?}");
            prop_assert!(!is_windows_absolute_path(&wrong_drive), "{wrong_drive:?}");
            prop_assert!(!is_windows_absolute_path(&bare), "{bare:?}");
            prop_assert!(!is_windows_absolute_path(&rooted), "{rooted:?}");
            if is_windows_absolute_path(&tail) {
                prop_assert!(has_drive_letter_prefix(&tail), "absolute without drive: {tail:?}");
            }
        }

        /// A string drawn from an alphabet without `*`, `?`, `[` has no glob
        /// syntax; planting one metacharacter anywhere makes it glob syntax;
        /// and the predicate distributes over concatenation.
        #[test]
        fn contains_glob_syntax_tracks_planted_metacharacters(
            left in "[a-zA-Z0-9_./ \\\\{}!-]{0,8}",
            right in "[a-zA-Z0-9_./ \\\\{}!-]{0,8}",
            meta in prop_oneof![literal("*"), literal("?"), literal("[")],
            a in any::<String>(),
            b in any::<String>(),
        ) {
            let plain = format!("{left}{right}");
            let planted = format!("{left}{meta}{right}");
            let concatenated = format!("{a}{b}");
            prop_assert!(!contains_glob_syntax(&plain), "{plain:?}");
            prop_assert!(contains_glob_syntax(&planted), "{planted:?}");
            prop_assert_eq!(
                contains_glob_syntax(&concatenated),
                contains_glob_syntax(&a) || contains_glob_syntax(&b),
            );
        }

        /// `rel_path_string` is the slash-joined spelling of the relative path
        /// components, with no backslash, for any component names.
        #[test]
        fn rel_path_string_joins_components_with_slashes(
            components in prop::collection::vec(
                prop_oneof![safe_component(), literal("na\u{ef}ve.rs"), literal("with space")],
                1..6,
            ),
        ) {
            let rel: PathBuf = components.iter().collect();
            let file = ProjectFile::new(std::env::temp_dir(), rel);
            let rendered = rel_path_string(&file);
            prop_assert_eq!(&rendered, &components.join("/"));
            prop_assert!(!rendered.contains('\\'));
        }

        /// `normalize_relative_path_from` against a stack-machine reference:
        /// names push, `.` is skipped, `..` pops and fails on an empty stack
        /// (the base counts as already on the stack, so `..` may consume it
        /// but not go past it). An accepted result is a fixed point when
        /// normalized again against the empty base.
        #[test]
        fn normalize_relative_path_from_matches_a_stack_reference(
            base in prop::collection::vec("[a-z]{1,2}", 0..4),
            tokens in prop::collection::vec(
                prop_oneof![
                    3 => "[a-z]{1,2}",
                    1 => literal("."),
                    2 => literal(".."),
                ],
                0..8,
            ),
        ) {
            let mut stack = base.clone();
            let mut escaped = false;
            for token in &tokens {
                match token.as_str() {
                    "." => {}
                    ".." => {
                        if stack.pop().is_none() {
                            escaped = true;
                            break;
                        }
                    }
                    name => stack.push(name.to_string()),
                }
            }
            let expected = (!escaped).then(|| stack.iter().collect::<PathBuf>());

            let base_path: PathBuf = base.iter().collect();
            let path: PathBuf = tokens.iter().collect();
            let actual = normalize_relative_path_from(&base_path, &path);
            prop_assert_eq!(&actual, &expected, "base {:?} path {:?}", base_path, path);
            if let Some(result) = actual {
                prop_assert_eq!(
                    normalize_relative_path_from(Path::new(""), &result),
                    Some(result.clone()),
                );
            }
        }

        /// Structure of the keys for any path: non-empty, strictly shortening,
        /// and each a component-boundary suffix of the one before it.
        #[test]
        fn path_suffix_keys_are_ordered_component_suffixes(input in adversarial_path()) {
            let path = PathBuf::from(&input);
            let keys = path_suffix_keys(&path);
            let key = path_suffix_key(&path);
            prop_assert_eq!(keys.is_empty(), key.is_none());
            prop_assert_eq!(keys.first().cloned(), key);

            let normal_count = path
                .components()
                .filter(|component| matches!(component, Component::Normal(_)))
                .count();
            prop_assert_eq!(keys.len(), normal_count);

            for window in keys.windows(2) {
                let (longer, shorter) = (&window[0], &window[1]);
                prop_assert!(!shorter.is_empty(), "empty key in {keys:?}");
                prop_assert!(longer.len() > shorter.len(), "not shortening: {keys:?}");
                prop_assert!(longer.ends_with(shorter.as_str()), "not a suffix: {keys:?}");
                let boundary = longer.len() - shorter.len() - 1;
                prop_assert_eq!(
                    longer.as_bytes()[boundary],
                    b'/',
                    "suffix does not start at a component boundary: {:?}",
                    keys,
                );
            }
            if let Some(last) = keys.last() {
                let expected = path
                    .components()
                    .filter_map(|component| match component {
                        Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
                        _ => None,
                    })
                    .next_back()
                    .expect("a suffix key exists only when a Normal component exists");
                prop_assert!(!last.is_empty(), "empty final key in {keys:?}");
                prop_assert_eq!(
                    last,
                    &expected,
                    "final key is not the final component: {:?}",
                    keys,
                );
            }
        }

        /// Totality: arbitrary text, including truncated and invalid escapes,
        /// decodes without panicking and never grows.
        #[test]
        fn percent_decode_is_total(
            input in prop_oneof![
                any::<String>(),
                adversarial_path(),
                "[%a-fA-F0-9zZ]{0,12}",
            ],
        ) {
            let decoded = percent_decode(&input);
            // Every output byte comes from one input byte or from a three-byte
            // escape, and lossy replacement of an escaped invalid byte costs at
            // most the three bytes that escape occupied.
            prop_assert!(
                decoded.len() <= input.len(),
                "{decoded:?} is longer than {input:?}",
            );
        }



        /// The decoder inverts a total `%XX` encoding of every byte, for any
        /// Unicode string.
        #[test]
        fn percent_decode_inverts_full_encoding(input in any::<String>()) {
            let encoded = percent_encode_all(&input);
            prop_assert_eq!(encoded.len(), input.len() * 3);
            prop_assert_eq!(percent_decode(&encoded), input);
        }
    }
}
