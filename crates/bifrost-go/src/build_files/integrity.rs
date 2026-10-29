//! Checksum observations and vendor snapshot syntax. Neither is MVS evidence.

use std::collections::HashMap;
use std::ops::Range;

use super::{
    BuildFileAtom, BuildFileIssue, BuildFileIssueKind, BuildFileLimits, GoDirective, SpannedToken,
    atom, issue, module_atom, quoted_atom, replacement, valid_go_release, version_atom,
};
use crate::packages::{GoModToken, valid_go_module_path};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoChecksumTarget {
    Module,
    Manifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoChecksumEntry {
    pub module: BuildFileAtom,
    /// Exact version, excluding the `/go.mod` suffix on manifest checksums.
    pub version: BuildFileAtom,
    pub target: GoChecksumTarget,
    pub checksum: BuildFileAtom,
    pub range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoChecksumDocument {
    pub entries: Vec<GoChecksumEntry>,
    pub issues: Vec<BuildFileIssue>,
}

impl GoChecksumDocument {
    /// Only the supported checksum-file syntax is complete. Entries do not
    /// establish which versions were selected, installed, or used.
    pub fn complete(&self) -> bool {
        self.issues.is_empty()
    }
}

/// Read either go.sum or go.work.sum from its explicitly supplied snapshot.
pub fn parse_go_sum(
    source: &str,
    limits: &BuildFileLimits,
    cancelled: impl Fn() -> bool,
) -> GoChecksumDocument {
    let mut entries = Vec::new();
    let mut seen = HashMap::new();
    let issues = visit_lines(source, limits, &cancelled, |line, range| {
        let [path, version, checksum] = line else {
            return Err(BuildFileIssueKind::Malformed);
        };
        if line
            .iter()
            .any(|token| !matches!(token.kind, GoModToken::Identifier(_)))
        {
            return Err(BuildFileIssueKind::Malformed);
        }
        let module = module_atom(path)?;
        let mut version = atom(version)?;
        let target = if let Some(value) = version.value.strip_suffix("/go.mod") {
            let len = value.len();
            version.value.truncate(len);
            version.range.end -= "/go.mod".len();
            GoChecksumTarget::Manifest
        } else {
            GoChecksumTarget::Module
        };
        let version_token = SpannedToken {
            kind: GoModToken::Identifier(version.value.clone()),
            range: version.range.clone(),
            comment: None,
        };
        version_atom(&version_token)?;
        let checksum = atom(checksum)?;
        let Some(digest) = checksum.value.strip_prefix("h1:") else {
            return Err(BuildFileIssueKind::Unsupported);
        };
        // A Go h1 checksum encodes 32 bytes in canonical padded base64. The
        // final sextet's two padding bits must be zero.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        if digest.len() != 44
            || !digest.ends_with('=')
            || !digest.as_bytes()[..43]
                .iter()
                .all(|byte| alphabet.contains(byte))
            || !alphabet
                .iter()
                .position(|byte| *byte == digest.as_bytes()[42])
                .is_some_and(|value| value % 4 == 0)
        {
            return Err(BuildFileIssueKind::Malformed);
        }
        let key = (module.value.clone(), version.value.clone(), target);
        let duplicate = seen.insert(key, checksum.value.clone());
        entries.push(GoChecksumEntry {
            module,
            version,
            target,
            checksum,
            range,
        });
        match duplicate {
            Some(previous) if previous != entries.last().unwrap().checksum.value => {
                Err(BuildFileIssueKind::Conflict)
            }
            Some(_) => Err(BuildFileIssueKind::Duplicate),
            None => Ok(()),
        }
    });
    GoChecksumDocument { entries, issues }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoVendorReplacement {
    pub source: BuildFileAtom,
    pub version: Option<BuildFileAtom>,
    pub local: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoVendorModule {
    pub module: BuildFileAtom,
    /// `None` for replacement-only headers. They do not prove vendoring.
    pub version: Option<BuildFileAtom>,
    pub replacement: Option<GoVendorReplacement>,
    pub header_range: Range<usize>,
    pub explicit: Option<Range<usize>>,
    pub declared_go: Option<BuildFileAtom>,
    pub packages: Vec<BuildFileAtom>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoVendorDocument {
    pub modules: Vec<GoVendorModule>,
    pub workspace: Option<Range<usize>>,
    pub issues: Vec<BuildFileIssue>,
}

impl GoVendorDocument {
    /// Complete syntax is not a validated or current selected graph. A caller
    /// must reconcile explicit declarations and replacements for the exact
    /// module/workspace snapshot before publishing any stronger evidence.
    pub fn complete(&self) -> bool {
        self.issues.is_empty()
    }
}

/// Read vendor/modules.txt syntax without opening any vendored source file.
pub fn parse_vendor_modules(
    source: &str,
    limits: &BuildFileLimits,
    cancelled: impl Fn() -> bool,
) -> GoVendorDocument {
    let mut modules: Vec<GoVendorModule> = Vec::new();
    let mut seen = HashMap::new();
    let mut workspace = None;
    let mut current = None;
    let issues = visit_lines(source, limits, &cancelled, |line, range| {
        let Some(GoModToken::Identifier(first)) = line.first().map(|token| &token.kind) else {
            return Err(BuildFileIssueKind::Malformed);
        };
        match first.as_str() {
            "#" => {
                // A malformed header must not attach subsequent package lines
                // to the previous, unrelated module.
                current = None;
                let (module, version, target) = if line.iter().any(
                    |token| matches!(&token.kind, GoModToken::Identifier(value) if value == "=>"),
                ) {
                    let GoDirective::Replace {
                        module,
                        version,
                        source,
                        source_version,
                        local,
                    } = replacement(&line[1..])?
                    else {
                        unreachable!("replacement decoder returns only replacements");
                    };
                    (
                        module,
                        version,
                        Some(GoVendorReplacement {
                            source,
                            version: source_version,
                            local,
                        }),
                    )
                } else {
                    let [_, path, version] = line else {
                        return Err(BuildFileIssueKind::Malformed);
                    };
                    (module_atom(path)?, Some(version_atom(version)?), None)
                };
                let key = (
                    module.value.clone(),
                    version.as_ref().map(|version| version.value.clone()),
                );
                let duplicate = seen.insert(key, modules.len()).is_some();
                current = Some(modules.len());
                modules.push(GoVendorModule {
                    module,
                    version,
                    replacement: target,
                    header_range: range,
                    explicit: None,
                    declared_go: None,
                    packages: Vec::new(),
                });
                if duplicate {
                    Err(BuildFileIssueKind::Duplicate)
                } else {
                    Ok(())
                }
            }
            "##" => {
                if matches!(line, [_, token] if matches!(&token.kind, GoModToken::Identifier(value) if value == "workspace"))
                {
                    if workspace.is_some() || !modules.is_empty() {
                        return Err(BuildFileIssueKind::Malformed);
                    }
                    workspace = Some(range);
                    return Ok(());
                }
                let Some(current) = current else {
                    return Err(BuildFileIssueKind::Malformed);
                };
                let module = &mut modules[current];
                let (explicit, go) = match &line[1..] {
                    [token] if matches!(&token.kind, GoModToken::Identifier(value) if value == "explicit") => {
                        (Some(token.range.clone()), None)
                    }
                    [token, go, version]
                        if matches!(&token.kind, GoModToken::Identifier(value) if value == "explicit;")
                            && matches!(&go.kind, GoModToken::Identifier(value) if value == "go") =>
                    {
                        (Some(token.range.start..token.range.end - 1), Some(version))
                    }
                    [go, version] if matches!(&go.kind, GoModToken::Identifier(value) if value == "go") => {
                        (None, Some(version))
                    }
                    _ => return Err(BuildFileIssueKind::Unsupported),
                };
                let go = go.map(atom).transpose()?;
                if go
                    .as_ref()
                    .is_some_and(|value| !valid_go_release(&value.value))
                {
                    return Err(BuildFileIssueKind::Malformed);
                }
                if (explicit.is_some() && module.explicit.is_some())
                    || (go.is_some() && module.declared_go.is_some())
                {
                    return Err(BuildFileIssueKind::Duplicate);
                }
                if explicit.is_some() {
                    module.explicit = explicit;
                }
                if go.is_some() {
                    module.declared_go = go;
                }
                Ok(())
            }
            _ => {
                let Some(current) = current else {
                    return Err(BuildFileIssueKind::Malformed);
                };
                let [package] = line else {
                    return Err(BuildFileIssueKind::Malformed);
                };
                let package = atom(package)?;
                let module = &mut modules[current];
                let matches_module = package.value == module.module.value
                    || package
                        .value
                        .strip_prefix(&module.module.value)
                        .is_some_and(|suffix| suffix.starts_with('/'));
                if !valid_go_module_path(&package.value)
                    || !matches_module
                    || module.version.is_none()
                {
                    return Err(BuildFileIssueKind::Malformed);
                }
                module.packages.push(package);
                Ok(())
            }
        }
    });
    GoVendorDocument {
        modules,
        workspace,
        issues,
    }
}

// Sum/vendor records have whitespace-separated fields, not Go comments.
// In particular, canonical base64 hashes may contain adjacent slash bytes.
fn lex_integrity(
    source: &str,
    limits: &BuildFileLimits,
    cancelled: &impl Fn() -> bool,
) -> Result<Vec<SpannedToken>, BuildFileIssue> {
    if source.len() > limits.max_bytes {
        return Err(issue(BuildFileIssueKind::ByteLimit, 0..source.len()));
    }
    let mut tokens = Vec::new();
    let mut offset = 0;
    while offset < source.len() {
        if cancelled() {
            return Err(issue(BuildFileIssueKind::Cancelled, offset..offset));
        }
        let start = offset;
        let character = source[offset..].chars().next().expect("in-bounds UTF-8");
        let kind = match character {
            ' ' | '\t' | '\r' => {
                offset += 1;
                continue;
            }
            '\n' => {
                offset += 1;
                GoModToken::Newline
            }
            '"' | '`' => quoted_atom(source, &mut offset, cancelled)?,
            _ => {
                while offset < source.len() {
                    if cancelled() {
                        return Err(issue(BuildFileIssueKind::Cancelled, start..offset));
                    }
                    let character = source[offset..].chars().next().expect("in-bounds UTF-8");
                    if matches!(character, ' ' | '\t' | '\r' | '\n') {
                        break;
                    }
                    offset += character.len_utf8();
                }
                GoModToken::Identifier(source[start..offset].to_owned())
            }
        };
        if tokens.len() >= limits.max_tokens {
            return Err(issue(BuildFileIssueKind::TokenLimit, start..offset));
        }
        tokens.push(SpannedToken {
            kind,
            range: start..offset,
            comment: None,
        });
    }
    Ok(tokens)
}

fn visit_lines(
    source: &str,
    limits: &BuildFileLimits,
    cancelled: &impl Fn() -> bool,
    mut visit: impl FnMut(&[SpannedToken], Range<usize>) -> Result<(), BuildFileIssueKind>,
) -> Vec<BuildFileIssue> {
    let tokens = match lex_integrity(source, limits, cancelled) {
        Ok(tokens) => tokens,
        Err(error) => return vec![error],
    };
    let mut issues = Vec::new();
    let mut cursor = 0;
    let mut lines = 0;
    while cursor < tokens.len() {
        if cancelled() {
            issues.push(issue(
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
        cursor += usize::from(cursor < tokens.len());
        if line.is_empty() {
            continue;
        }
        let range = line[0].range.start..line.last().unwrap().range.end;
        if lines >= limits.max_entries {
            issues.push(issue(BuildFileIssueKind::EntryLimit, range));
            break;
        }
        lines += 1;
        if let Err(kind) = visit(line, range.clone()) {
            issues.push(issue(kind, range));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn integrity_fields_preserve_literal_slashes_and_quoted_paths() {
        let hash = "h1://////////////////////////////////////////8=";
        let source = format!("example.com/lib v1.0.0 {hash}\n");
        let sum = parse_go_sum(&source, &Default::default(), || false);
        assert!(sum.complete(), "{sum:?}");
        assert_eq!(sum.entries[0].checksum.value, hash);
        assert_eq!(&source[sum.entries[0].checksum.range.clone()], hash);
        let vendor = parse_vendor_modules(
            "# example.com/lib v1.0.0 => \"../local path//child\"\n## explicit\n",
            &Default::default(),
            || false,
        );
        assert!(vendor.complete(), "{vendor:?}");
        assert_eq!(
            vendor.modules[0].replacement.as_ref().unwrap().source.value,
            "../local path//child"
        );
        let malformed = parse_go_sum(
            &format!("example.com/lib v1.0.0 {HASH} // comment\n"),
            &Default::default(),
            || false,
        );
        assert!(!malformed.complete());
    }

    #[test]
    fn sum_observations_preserve_historical_versions_and_checksum_targets() {
        let source =
            format!("example.com/lib/v2 v2.0.0 {HASH}\nexample.com/lib/v2 v2.1.0/go.mod {HASH}\n");
        let document = parse_go_sum(&source, &BuildFileLimits::default(), || false);
        assert!(document.complete(), "{:?}", document.issues);
        assert_eq!(document.entries.len(), 2);
        assert_eq!(document.entries[0].version.value, "v2.0.0");
        assert_eq!(document.entries[1].version.value, "v2.1.0");
        assert_eq!(document.entries[1].target, GoChecksumTarget::Manifest);
        assert_eq!(&source[document.entries[1].version.range.clone()], "v2.1.0");
    }

    #[test]
    fn unsupported_corrupt_and_conflicting_checksums_remain_explicit() {
        for (source, kind) in [
            (
                "example.com/lib v1.0.0 h2:unknown\n".to_owned(),
                BuildFileIssueKind::Unsupported,
            ),
            (
                "example.com/lib v1.0.0 h1:broken\n".to_owned(),
                BuildFileIssueKind::Malformed,
            ),
            (
                format!(
                    "example.com/lib v1.0.0 {HASH}\nexample.com/lib v1.0.0 h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=\n"
                ),
                BuildFileIssueKind::Conflict,
            ),
        ] {
            let document = parse_go_sum(&source, &BuildFileLimits::default(), || false);
            assert!(!document.complete(), "{source}");
            assert_eq!(document.issues[0].kind, kind);
        }
    }

    #[test]
    fn vendor_snapshots_keep_explicit_go_and_replacement_only_headers_separate() {
        let source = "## workspace\n# example.com/lib v1.2.0 => ../local\n## explicit; go 1.26\nexample.com/lib/sub\n# example.com/other/v2 v2.1.0 => example.com/fork/v2 v2.2.0\n## explicit\nexample.com/other/v2\n# example.com/unused => ../unused\n";
        let document = parse_vendor_modules(source, &BuildFileLimits::default(), || false);
        assert!(document.complete(), "{:?}", document.issues);
        assert_eq!(document.modules.len(), 3);
        assert!(document.workspace.is_some());
        let local = &document.modules[0];
        assert!(local.replacement.as_ref().unwrap().local);
        assert_eq!(local.declared_go.as_ref().unwrap().value, "1.26");
        assert_eq!(&source[local.explicit.clone().unwrap()], "explicit");
        let fork = &document.modules[1];
        assert_eq!(fork.module.value, "example.com/other/v2");
        assert_eq!(
            fork.replacement.as_ref().unwrap().source.value,
            "example.com/fork/v2"
        );
        assert!(document.modules[2].version.is_none());
        assert!(document.modules[2].packages.is_empty());
    }

    #[test]
    fn invalid_vendor_headers_do_not_claim_the_previous_module() {
        let source =
            "# example.com/lib v1.0.0\nexample.com/lib/sub\n# corrupt\nexample.com/lib/another\n";
        let document = parse_vendor_modules(source, &BuildFileLimits::default(), || false);
        assert!(!document.complete());
        assert_eq!(document.modules[0].packages.len(), 1);
        assert_eq!(document.issues.len(), 2);
    }

    #[test]
    fn integrity_byte_limit_includes_the_exact_snapshot_boundary() {
        let source = format!("example.com/lib v1.0.0 {HASH}\n");
        for extra in [0, 1] {
            let document = parse_go_sum(
                &source,
                &BuildFileLimits {
                    max_bytes: source.len() + extra,
                    ..Default::default()
                },
                || false,
            );
            assert!(document.complete(), "{document:?}");
            assert_eq!(document.entries.len(), 1);
        }
        let document = parse_go_sum(
            &source,
            &BuildFileLimits {
                max_bytes: source.len() - 1,
                ..Default::default()
            },
            || false,
        );
        assert_eq!(document.issues[0].kind, BuildFileIssueKind::ByteLimit);
        assert!(document.entries.is_empty());
    }

    #[test]
    fn integrity_readers_enforce_limits_and_cancellation() {
        let source = format!("example.com/lib v1.0.0 {HASH}\nexample.com/lib v1.1.0 {HASH}\n");
        let document = parse_go_sum(
            &source,
            &BuildFileLimits {
                max_entries: 1,
                ..Default::default()
            },
            || false,
        );
        assert_eq!(document.entries.len(), 1);
        assert_eq!(document.issues[0].kind, BuildFileIssueKind::EntryLimit);
        let document = parse_vendor_modules(
            "# example.com/lib v1.0.0\n",
            &BuildFileLimits::default(),
            || true,
        );
        assert_eq!(document.issues[0].kind, BuildFileIssueKind::Cancelled);
    }
}
