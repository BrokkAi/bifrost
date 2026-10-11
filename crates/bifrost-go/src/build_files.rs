//! Syntax readers for exact, explicitly supplied Go build-file snapshots.
//!
//! These are ecosystem syntax records, not a dependency inventory or an MVS
//! resolution. A require version is a declared minimum, a checksum is only an
//! integrity observation, and a replacement is a source relation. Adapters
//! must preserve those distinctions in the shared dependency-evidence contract.
//! No reader performs I/O, starts Go, or retains state between calls.

mod integrity;
pub use integrity::{
    GoChecksumDocument, GoChecksumEntry, GoChecksumTarget, GoVendorDocument, GoVendorModule,
    GoVendorReplacement, parse_go_sum, parse_vendor_modules,
};

use std::collections::HashSet;
use std::ops::Range;

use crate::packages::{GoModToken, valid_go_module_path};

/// Limits apply to one supplied document, before allocating its token stream.
#[derive(Debug, Clone, Copy)]
pub struct BuildFileLimits {
    pub max_bytes: usize,
    pub max_tokens: usize,
    pub max_entries: usize,
}

impl Default for BuildFileLimits {
    fn default() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024,
            max_tokens: 1_000_000,
            max_entries: 100_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildFileIssueKind {
    Malformed,
    Unsupported,
    Duplicate,
    Conflict,
    ByteLimit,
    TokenLimit,
    EntryLimit,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildFileIssue {
    pub kind: BuildFileIssueKind,
    /// Half-open byte offsets into the exact supplied document.
    pub range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildFileAtom {
    /// Decoded lexical value; versions are never normalized or coerced.
    pub value: String,
    pub range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoDirective {
    Module(BuildFileAtom),
    Require {
        module: BuildFileAtom,
        version: BuildFileAtom,
        /// Exact `// indirect` annotation, if present.
        indirect: Option<Range<usize>>,
    },
    Replace {
        module: BuildFileAtom,
        version: Option<BuildFileAtom>,
        source: BuildFileAtom,
        source_version: Option<BuildFileAtom>,
        /// A local source has no established version, even if its module name
        /// resembles the original dependency.
        local: bool,
    },
    Exclude {
        module: BuildFileAtom,
        version: BuildFileAtom,
    },
    Go(BuildFileAtom),
    Toolchain(BuildFileAtom),
    Use(BuildFileAtom),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoDirectiveEntry {
    pub directive: GoDirective,
    /// The directive keyword, including the keyword of a surrounding block.
    pub keyword_range: Range<usize>,
    /// Exact argument line; for a direct directive also includes the keyword.
    pub range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoBuildDocument {
    pub entries: Vec<GoDirectiveEntry>,
    pub issues: Vec<BuildFileIssue>,
}

impl GoBuildDocument {
    /// Completeness of supported declaration syntax, never graph selection.
    pub fn complete(&self) -> bool {
        self.issues.is_empty()
    }
}

#[derive(Debug)]
pub(crate) struct SpannedToken {
    pub kind: GoModToken,
    pub range: Range<usize>,
    // Comments are attached to the next newline (or final EOF marker), so the
    // legacy module recognizer consumes the same token kinds as before.
    comment: Option<Range<usize>>,
}

/// The existing go.mod lexer, now shared by identity and evidence readers.
pub(crate) fn lex(
    contents: &str,
    limits: &BuildFileLimits,
    cancelled: &impl Fn() -> bool,
) -> Result<Vec<SpannedToken>, BuildFileIssue> {
    if contents.len() > limits.max_bytes {
        return Err(issue(BuildFileIssueKind::ByteLimit, 0..contents.len()));
    }
    let mut tokens = Vec::new();
    let mut offset = 0;
    let mut comment = None;
    while offset < contents.len() {
        if cancelled() {
            return Err(issue(BuildFileIssueKind::Cancelled, offset..offset));
        }
        let start = offset;
        let character = contents[offset..].chars().next().expect("in-bounds UTF-8");
        let kind = match character {
            ' ' | '\t' | '\r' => {
                offset += character.len_utf8();
                continue;
            }
            '\n' => {
                offset += 1;
                GoModToken::Newline
            }
            '/' if contents[offset..].starts_with("//") => {
                while offset < contents.len() && contents.as_bytes()[offset] != b'\n' {
                    if cancelled() {
                        return Err(issue(BuildFileIssueKind::Cancelled, start..offset));
                    }
                    offset += contents[offset..]
                        .chars()
                        .next()
                        .expect("in-bounds UTF-8")
                        .len_utf8();
                }
                comment = Some(start..offset);
                continue;
            }
            '(' => {
                offset += 1;
                GoModToken::LeftParen
            }
            ')' => {
                offset += 1;
                GoModToken::RightParen
            }
            '"' | '`' => quoted_atom(contents, &mut offset, cancelled)?,
            _ => {
                while offset < contents.len() {
                    if cancelled() {
                        return Err(issue(BuildFileIssueKind::Cancelled, start..offset));
                    }
                    let character = contents[offset..].chars().next().expect("in-bounds UTF-8");
                    if matches!(character, ' ' | '\t' | '\r' | '\n' | '(' | ')')
                        || contents[offset..].starts_with("//")
                    {
                        break;
                    }
                    offset += character.len_utf8();
                }
                assert!(offset > start, "go.mod scanner must make progress");
                GoModToken::Identifier(contents[start..offset].to_owned())
            }
        };
        if tokens.len() >= limits.max_tokens {
            return Err(issue(BuildFileIssueKind::TokenLimit, start..offset));
        }
        let trailing_comment = if matches!(kind, GoModToken::Newline) {
            comment.take()
        } else {
            None
        };
        tokens.push(SpannedToken {
            kind,
            range: start..offset,
            comment: trailing_comment,
        });
    }
    if comment.is_some() {
        if tokens.len() >= limits.max_tokens {
            return Err(issue(BuildFileIssueKind::TokenLimit, offset..offset));
        }
        tokens.push(SpannedToken {
            kind: GoModToken::Newline,
            range: offset..offset,
            comment,
        });
    }
    Ok(tokens)
}

fn issue(kind: BuildFileIssueKind, range: Range<usize>) -> BuildFileIssue {
    BuildFileIssue { kind, range }
}

// Quote decoding is shared by declaration and integrity grammars; comment
// recognition belongs only to the declaration lexer.
fn quoted_atom(
    contents: &str,
    offset: &mut usize,
    cancelled: &impl Fn() -> bool,
) -> Result<GoModToken, BuildFileIssue> {
    let start = *offset;
    let delimiter = contents[*offset..].chars().next().expect("quote start");
    *offset += delimiter.len_utf8();
    let mut value = Vec::new();
    while *offset < contents.len() {
        if cancelled() {
            return Err(issue(BuildFileIssueKind::Cancelled, start..*offset));
        }
        let character = contents[*offset..].chars().next().expect("in-bounds UTF-8");
        *offset += character.len_utf8();
        if character == delimiter {
            return String::from_utf8(value)
                .map(GoModToken::String)
                .map_err(|_| issue(BuildFileIssueKind::Unsupported, start..*offset));
        }
        if delimiter == '"' && character == '\\' {
            let Some(escaped) = contents[*offset..].chars().next() else {
                return Err(issue(BuildFileIssueKind::Malformed, start..*offset));
            };
            *offset += escaped.len_utf8();
            match escaped {
                '\\' | '"' => value.push(escaped as u8),
                'a' => value.push(7),
                'b' => value.push(8),
                'f' => value.push(12),
                'n' => value.push(b'\n'),
                'r' => value.push(b'\r'),
                't' => value.push(b'\t'),
                'v' => value.push(11),
                'x' | 'u' | 'U' | '0'..='7' => {
                    let (radix, digits, mut scalar) = match escaped {
                        'x' => (16, 2, 0),
                        'u' => (16, 4, 0),
                        'U' => (16, 8, 0),
                        _ => (8, 2, escaped.to_digit(8).unwrap()),
                    };
                    for _ in 0..digits {
                        if cancelled() {
                            return Err(issue(BuildFileIssueKind::Cancelled, start..*offset));
                        }
                        let digit = contents[*offset..]
                            .chars()
                            .next()
                            .and_then(|digit| digit.to_digit(radix))
                            .ok_or_else(|| issue(BuildFileIssueKind::Malformed, start..*offset))?;
                        *offset += 1; // radix digits are ASCII
                        scalar = scalar * radix + digit;
                    }
                    if matches!(escaped, 'u' | 'U') {
                        let rune = char::from_u32(scalar)
                            .ok_or_else(|| issue(BuildFileIssueKind::Malformed, start..*offset))?;
                        value.extend_from_slice(rune.encode_utf8(&mut [0; 4]).as_bytes());
                    } else {
                        let byte = u8::try_from(scalar)
                            .map_err(|_| issue(BuildFileIssueKind::Malformed, start..*offset))?;
                        value.push(byte);
                    }
                }
                _ => return Err(issue(BuildFileIssueKind::Malformed, start..*offset)),
            }
        } else if delimiter != '`' || character != '\r' {
            value.extend_from_slice(character.encode_utf8(&mut [0; 4]).as_bytes());
        }
    }
    Err(issue(BuildFileIssueKind::Malformed, start..*offset))
}

/// Parse module declarations. No directive establishes a selected version.
pub fn parse_go_mod(
    source: &str,
    limits: &BuildFileLimits,
    cancelled: impl Fn() -> bool,
) -> GoBuildDocument {
    let mut document = parse_directives(source, limits, &cancelled, module_directive);
    if !document
        .entries
        .iter()
        .any(|entry| matches!(entry.directive, GoDirective::Module(_)))
    {
        document
            .issues
            .push(issue(BuildFileIssueKind::Malformed, 0..0));
    }
    document
}

/// Parse workspace membership and workspace replacement declarations.
pub fn parse_go_work(
    source: &str,
    limits: &BuildFileLimits,
    cancelled: impl Fn() -> bool,
) -> GoBuildDocument {
    parse_directives(source, limits, &cancelled, workspace_directive)
}

type DirectiveDecoder =
    fn(&str, &[SpannedToken], Option<Range<usize>>) -> Result<GoDirective, BuildFileIssueKind>;

fn parse_directives(
    source: &str,
    limits: &BuildFileLimits,
    cancelled: &impl Fn() -> bool,
    decode: DirectiveDecoder,
) -> GoBuildDocument {
    let mut document = GoBuildDocument {
        entries: Vec::new(),
        issues: Vec::new(),
    };
    let tokens = match lex(source, limits, cancelled) {
        Ok(tokens) => tokens,
        Err(error) => {
            document.issues.push(error);
            return document;
        }
    };
    let mut cursor = 0;
    let mut block: Option<(&str, Range<usize>)> = None;
    let mut seen = HashSet::new();
    let mut lines = 0;
    while cursor < tokens.len() {
        if cancelled() {
            document.issues.push(issue(
                BuildFileIssueKind::Cancelled,
                tokens[cursor].range.clone(),
            ));
            break;
        }
        let start = cursor;
        while cursor < tokens.len() && !matches!(tokens[cursor].kind, GoModToken::Newline) {
            cursor += 1;
        }
        let line = &tokens[start..cursor];
        let comment = tokens.get(cursor).and_then(|token| token.comment.clone());
        cursor += usize::from(cursor < tokens.len());
        if line.is_empty() {
            continue;
        }
        if lines >= limits.max_entries {
            document
                .issues
                .push(issue(BuildFileIssueKind::EntryLimit, line[0].range.clone()));
            break;
        }
        lines += 1;
        let range = line[0].range.start
            ..comment
                .as_ref()
                .map_or(line.last().unwrap().range.end, |span| span.end);
        if matches!(line[0].kind, GoModToken::RightParen) {
            if line.len() != 1 || block.take().is_none() {
                document
                    .issues
                    .push(issue(BuildFileIssueKind::Malformed, range));
            }
            continue;
        }
        let (keyword, keyword_range, args) = if let Some((keyword, span)) = &block {
            (*keyword, span.clone(), line)
        } else {
            let GoModToken::Identifier(keyword) = &line[0].kind else {
                document
                    .issues
                    .push(issue(BuildFileIssueKind::Malformed, range));
                continue;
            };
            if line.len() == 2 && matches!(line[1].kind, GoModToken::LeftParen) {
                if matches!(
                    decode(keyword, &[], None),
                    Err(BuildFileIssueKind::Unsupported)
                ) {
                    document
                        .issues
                        .push(issue(BuildFileIssueKind::Unsupported, range));
                }
                block = Some((keyword.as_str(), line[0].range.clone()));
                continue;
            }
            (keyword.as_str(), line[0].range.clone(), &line[1..])
        };
        let indirect = comment.filter(|span| {
            source[span.clone()]
                .strip_prefix("//")
                .is_some_and(|comment| comment.trim() == "indirect")
        });
        match decode(keyword, args, indirect) {
            Ok(directive) => {
                let identity = match &directive {
                    GoDirective::Module(_) | GoDirective::Go(_) | GoDirective::Toolchain(_) => {
                        String::new()
                    }
                    GoDirective::Require { module, .. } => module.value.clone(),
                    GoDirective::Exclude { module, version } => {
                        format!("{}@{}", module.value, version.value)
                    }
                    GoDirective::Replace {
                        module, version, ..
                    } => format!(
                        "{}@{}",
                        module.value,
                        version.as_ref().map_or("", |v| &v.value)
                    ),
                    GoDirective::Use(path) => path.value.clone(),
                };
                if !seen.insert((keyword, identity)) {
                    document
                        .issues
                        .push(issue(BuildFileIssueKind::Duplicate, range.clone()));
                }
                document.entries.push(GoDirectiveEntry {
                    directive,
                    keyword_range,
                    range,
                });
            }
            Err(kind) => document.issues.push(issue(kind, range)),
        }
    }
    if let Some((_, span)) = block {
        document
            .issues
            .push(issue(BuildFileIssueKind::Malformed, span));
    }
    document
}

fn atom(token: &SpannedToken) -> Result<BuildFileAtom, BuildFileIssueKind> {
    let value = match &token.kind {
        GoModToken::Identifier(value) | GoModToken::String(value) => value,
        _ => return Err(BuildFileIssueKind::Malformed),
    };
    if value.is_empty()
        || value
            .chars()
            .any(|character| matches!(character, '\n' | '\r' | '\0'))
    {
        return Err(BuildFileIssueKind::Malformed);
    }
    Ok(BuildFileAtom {
        value: value.clone(),
        range: token.range.clone(),
    })
}

fn module_atom(token: &SpannedToken) -> Result<BuildFileAtom, BuildFileIssueKind> {
    let value = atom(token)?;
    if !valid_go_module_path(&value.value) {
        return Err(BuildFileIssueKind::Malformed);
    }
    Ok(value)
}

fn module_directive(
    keyword: &str,
    args: &[SpannedToken],
    indirect: Option<Range<usize>>,
) -> Result<GoDirective, BuildFileIssueKind> {
    match (keyword, args) {
        ("module", [path]) => Ok(GoDirective::Module(module_atom(path)?)),
        ("require", [path, version]) => Ok(GoDirective::Require {
            module: module_atom(path)?,
            version: version_atom(version)?,
            indirect,
        }),
        ("exclude", [path, version]) => Ok(GoDirective::Exclude {
            module: module_atom(path)?,
            version: version_atom(version)?,
        }),
        ("replace", _) => replacement(args),
        ("go" | "toolchain", _) => toolchain_directive(keyword, args),
        ("module" | "require" | "exclude", _) => Err(BuildFileIssueKind::Malformed),
        _ => Err(BuildFileIssueKind::Unsupported),
    }
}

fn workspace_directive(
    keyword: &str,
    args: &[SpannedToken],
    _indirect: Option<Range<usize>>,
) -> Result<GoDirective, BuildFileIssueKind> {
    match (keyword, args) {
        ("use", [path]) => Ok(GoDirective::Use(atom(path)?)),
        ("replace", _) => replacement(args),
        ("go" | "toolchain", _) => toolchain_directive(keyword, args),
        ("use", _) => Err(BuildFileIssueKind::Malformed),
        _ => Err(BuildFileIssueKind::Unsupported),
    }
}

fn toolchain_directive(
    keyword: &str,
    args: &[SpannedToken],
) -> Result<GoDirective, BuildFileIssueKind> {
    let [token] = args else {
        return Err(BuildFileIssueKind::Malformed);
    };
    let value = atom(token)?;
    match keyword {
        "go" => {
            if !valid_go_release(&value.value) {
                return Err(BuildFileIssueKind::Malformed);
            }
            Ok(GoDirective::Go(value))
        }
        "toolchain" => {
            if value.value != "default"
                && !value.value.strip_prefix("go").is_some_and(valid_go_release)
            {
                return Err(BuildFileIssueKind::Malformed);
            }
            Ok(GoDirective::Toolchain(value))
        }
        _ => unreachable!("only toolchain directives are passed"),
    }
}

fn valid_go_release(value: &str) -> bool {
    let release = value.split_once("rc").or_else(|| value.split_once("beta"));
    let base = release.map_or(value, |(base, _)| base);
    let mut parts = base.split('.');
    let Some(major) = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    let patch = parts.next();
    major == "1"
        && numeric(minor)
        && patch.is_none_or(numeric)
        && parts.next().is_none()
        && release.is_none_or(|(_, suffix)| numeric(suffix))
}

fn numeric(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
}

fn version_atom(token: &SpannedToken) -> Result<BuildFileAtom, BuildFileIssueKind> {
    let value = atom(token)?;
    // Validate canonical Go module-version syntax without semver coercion;
    // pseudo-versions and +incompatible remain exact lexical values.
    let Some(version) = value.value.strip_prefix('v') else {
        return Err(BuildFileIssueKind::Malformed);
    };
    let (version, build) = version
        .split_once('+')
        .map_or((version, None), |(version, build)| (version, Some(build)));
    let (base, prerelease) = version
        .split_once('-')
        .map_or((version, None), |(base, pre)| (base, Some(pre)));
    let mut numbers = base.split('.');
    if !(numbers.next().is_some_and(numeric)
        && numbers.next().is_some_and(numeric)
        && numbers.next().is_some_and(numeric)
        && numbers.next().is_none())
        || build.is_some_and(|build| build != "incompatible")
        || prerelease.is_some_and(|pre| {
            pre.split('.').any(|part| {
                part.is_empty()
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    || (part.bytes().all(|byte| byte.is_ascii_digit()) && !numeric(part))
            })
        })
    {
        return Err(BuildFileIssueKind::Malformed);
    }
    Ok(value)
}

fn replacement(args: &[SpannedToken]) -> Result<GoDirective, BuildFileIssueKind> {
    let Some(arrow) = args
        .iter()
        .position(|token| matches!(&token.kind, GoModToken::Identifier(value) if value == "=>"))
    else {
        return Err(BuildFileIssueKind::Malformed);
    };
    let (module, version) = match &args[..arrow] {
        [path] => (module_atom(path)?, None),
        [path, version] => (module_atom(path)?, Some(version_atom(version)?)),
        _ => return Err(BuildFileIssueKind::Malformed),
    };
    let (source, source_version, local) = match &args[arrow + 1..] {
        [path] => {
            let source = atom(path)?;
            let path = source.value.as_str();
            let local = path == "."
                || path == ".."
                || path.starts_with("./")
                || path.starts_with("../")
                || path.starts_with('/')
                || path.starts_with(".\\")
                || path.starts_with("..\\")
                || path.starts_with("\\\\")
                || (path.as_bytes().get(1) == Some(&b':')
                    && path.as_bytes()[0].is_ascii_alphabetic()
                    && matches!(path.as_bytes().get(2), Some(b'/' | b'\\')));
            if !local {
                return Err(BuildFileIssueKind::Malformed);
            }
            (source, None, true)
        }
        [path, version] => (module_atom(path)?, Some(version_atom(version)?), false),
        _ => return Err(BuildFileIssueKind::Malformed),
    };
    Ok(GoDirective::Replace {
        module,
        version,
        source,
        source_version,
        local,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(source: &str) -> GoBuildDocument {
        parse_go_mod(source, &BuildFileLimits::default(), || false)
    }

    #[test]
    fn quoted_escapes_do_not_manufacture_module_identity() {
        for (source, kind) in [
            (
                "module \"example.com/lib\\q\"\n",
                BuildFileIssueKind::Malformed,
            ),
            (
                "module \"example.com/lib\\n\"\n",
                BuildFileIssueKind::Malformed,
            ),
            (
                "module \"example.com/lib\\xff\"\n",
                BuildFileIssueKind::Unsupported,
            ),
        ] {
            let document = module(source);
            assert!(!document.complete(), "{document:?}");
            assert_eq!(document.issues[0].kind, kind);
        }
        let escaped = module("module \"example.com/\\162\\x65\\u0070\\U0000006f\"\n");
        assert!(escaped.complete(), "{escaped:?}");
        assert!(
            matches!(&escaped.entries[0].directive, GoDirective::Module(path) if path.value == "example.com/repo")
        );
    }

    #[test]
    fn declarations_retain_versions_indirect_annotation_and_exact_source() {
        let source = "module example.com/app/v2\r\ngo 1.26\r\ntoolchain go1.26.1\r\nrequire (\r\n\t\"example.com/lib/v2\" v2.0.0-20260102030405-abcdef123456 // indirect\r\n)\r\nexclude example.com/lib/v2 v2.1.0\r\n";
        let document = module(source);
        assert!(document.complete(), "{:?}", document.issues);
        let entry = &document.entries[3];
        let GoDirective::Require {
            module,
            version,
            indirect,
        } = &entry.directive
        else {
            panic!("require");
        };
        assert_eq!(module.value, "example.com/lib/v2");
        assert_eq!(&source[module.range.clone()], "\"example.com/lib/v2\"");
        assert_eq!(version.value, "v2.0.0-20260102030405-abcdef123456");
        assert_eq!(&source[version.range.clone()], version.value);
        assert_eq!(&source[indirect.clone().unwrap()], "// indirect\r");
        assert_eq!(&source[entry.keyword_range.clone()], "require");
        assert!(matches!(
            document.entries[4].directive,
            GoDirective::Exclude { .. }
        ));
    }

    #[test]
    fn workspace_members_and_replacement_sources_retain_identity() {
        let source = "go 1.26\nuse (\n ./affected\n ./fixed\n ./missing\n)\nreplace (\n example.com/lib v1.2.0 => ../local\n example.com/other => example.com/fork/v2 v2.1.0\n)\n";
        let document = parse_go_work(source, &BuildFileLimits::default(), || false);
        assert!(document.complete(), "{:?}", document.issues);
        assert!(
            matches!(&document.entries[3].directive, GoDirective::Use(path) if path.value == "./missing")
        );
        assert!(matches!(&document.entries[4].directive,
            GoDirective::Replace { module, version: Some(version), source, source_version: None, local: true }
            if module.value == "example.com/lib" && version.value == "v1.2.0" && source.value == "../local"));
        assert!(matches!(&document.entries[5].directive,
            GoDirective::Replace { source, source_version: Some(version), local: false, .. }
            if source.value == "example.com/fork/v2" && version.value == "v2.1.0"));
    }

    #[test]
    fn malformed_and_unsupported_syntax_never_reports_complete() {
        for source in [
            "module example.com/app\nrequire example.com/lib\n",
            "module example.com/app\nrequire (\n example.com/lib v1.0.0\n",
            "module example.com/app\nreplace example.com/lib => example.com/fork\n",
            "module example.com/app\nreplace example.com/lib => ../local v1.0.0\n",
            "module example.com/app\nrequire example.com/lib v1.02.0\n",
            "module example.com/app\nrequire example.com/lib v1.0.0-01\n",
            "module example.com/app\nrequire example.com/lib \"v1.0.0\n",
            "module example.com/app\ngodebug (\n)\n",
            "module example.com/app\n)\n",
        ] {
            let document = module(source);
            assert!(!document.complete(), "{source:?}");
            assert!(!document.issues.is_empty());
        }
    }

    #[test]
    fn conflicting_declarations_remain_visible_and_incomplete() {
        let document = module(
            "module example.com/app\nrequire example.com/lib v1.0.0\nrequire example.com/lib v1.1.0\nmodule example.com/other\n",
        );
        assert_eq!(document.entries.len(), 4);
        assert_eq!(
            document
                .issues
                .iter()
                .filter(|error| error.kind == BuildFileIssueKind::Duplicate)
                .count(),
            2
        );
        assert!(!document.complete());
    }

    #[test]
    fn multiple_modules_remain_separate_declaration_documents() {
        let affected = module("module example.com/affected\nrequire example.com/lib v1.2.0\n");
        let fixed = module("module example.com/fixed\nrequire example.com/lib v1.3.0\n");
        assert!(affected.complete() && fixed.complete());
        let GoDirective::Require { version: first, .. } = &affected.entries[1].directive else {
            panic!("require");
        };
        let GoDirective::Require {
            version: second, ..
        } = &fixed.entries[1].directive
        else {
            panic!("require");
        };
        assert_eq!(first.value, "v1.2.0");
        assert_eq!(second.value, "v1.3.0");
    }

    #[test]
    fn bounds_and_cancellation_are_explicit() {
        let source = "module example.com/app\nrequire example.com/lib v1.0.0\n";
        for (limits, expected) in [
            (
                BuildFileLimits {
                    max_bytes: 1,
                    ..Default::default()
                },
                BuildFileIssueKind::ByteLimit,
            ),
            (
                BuildFileLimits {
                    max_tokens: 1,
                    ..Default::default()
                },
                BuildFileIssueKind::TokenLimit,
            ),
            (
                BuildFileLimits {
                    max_entries: 1,
                    ..Default::default()
                },
                BuildFileIssueKind::EntryLimit,
            ),
        ] {
            let document = parse_go_mod(source, &limits, || false);
            assert!(!document.complete());
            assert_eq!(document.issues[0].kind, expected);
        }
        let document = parse_go_work(source, &BuildFileLimits::default(), || true);
        assert_eq!(document.issues[0].kind, BuildFileIssueKind::Cancelled);
    }
}
