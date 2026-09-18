//! MCP `report_secret_like_code` handler. Ports brokk's git-backed
//! secret scanner and the brokk-core MCP wrapper to bifrost.

use super::{ReportLines, sanitize_table_cell};
use crate::analyzer::test_paths;
use crate::analyzer::{IAnalyzer, Language, parser_language_for_path};
use crate::gitblob::resolve_default_branch_ref;
use crate::path_utils::normalize_pattern;
use git2::{FileMode, ObjectType, Oid, Repository, Sort, TreeWalkMode, TreeWalkResult};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use tree_sitter::{Node, Parser};

const DEFAULT_SECRET_MAX_FINDINGS: i32 = 100;
const DEFAULT_SECRET_MAX_COMMITS: i32 = 2000;
const MAX_BLOB_BYTES: usize = 1024 * 1024;
const MAX_SECRET_SAMPLE_VALUE_CHARS: usize = 12;
const MAX_EXCERPT_CHARS: usize = 120;

static PLACEHOLDER_VALUES: &[&str] = &[
    "changeme",
    "change_me",
    "example",
    "example-secret",
    "dummy",
    "test",
    "testing",
    "placeholder",
    "password",
    "secret",
    "token",
    "xxx",
    "xxxx",
    "your-token",
    "your-secret",
];

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReportSecretLikeCodeParams {
    #[serde(default)]
    pub max_findings: i32,
    #[serde(default)]
    pub max_commits: i32,
    #[serde(default)]
    pub include_history_only: bool,
    #[serde(default)]
    pub include_low_confidence: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportSecretLikeCodeResult {
    pub report: String,
    pub truncated: bool,
    pub findings: Vec<SecretFinding>,
    pub diagnostics: Vec<SecretScanDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum SecretConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum SecretLocation {
    Current,
    History,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct SecretRedactionSpan {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum SecretScanDiagnosticKind {
    UnsupportedAssignmentSyntax,
    UnparseableAssignmentSyntax,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct SecretScanDiagnostic {
    pub path: String,
    pub kind: SecretScanDiagnosticKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SecretKey {
    path: String,
    line: usize,
    rule: String,
    confidence: SecretConfidence,
    sample: String,
    redaction_span: SecretRedactionSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretFinding {
    pub path: String,
    pub line: usize,
    pub rule: String,
    pub confidence: SecretConfidence,
    pub location: SecretLocation,
    pub first_seen_commit: String,
    pub last_seen_commit: String,
    pub sample: String,
    pub redaction_span: SecretRedactionSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SecretScanReport {
    repository: String,
    default_ref_display_name: String,
    default_ref_fallback: bool,
    max_commits: usize,
    commits_scanned: usize,
    missing_entries_skipped: usize,
    non_text_entries_skipped: usize,
    findings: Vec<SecretFinding>,
    diagnostics: Vec<SecretScanDiagnostic>,
}

struct GitContext {
    repo: Repository,
    repo_root: PathBuf,
    project_root: PathBuf,
}

#[derive(Debug, Clone)]
struct BlobScanResult {
    keys: HashSet<SecretKey>,
    diagnostics: Vec<SecretScanDiagnostic>,
    blobs_scanned: usize,
    missing_entries_skipped: usize,
    non_text_entries_skipped: usize,
}

#[derive(Debug, Clone, Default)]
struct CurrentScanResult {
    keys: HashSet<SecretKey>,
    diagnostics: Vec<SecretScanDiagnostic>,
}

#[derive(Debug, Clone, Default)]
struct HistoryScanAccumulator {
    keys_by_commit: HashMap<String, HashSet<SecretKey>>,
    commit_order: HashMap<String, isize>,
    commits_scanned: usize,
    blobs_scanned: usize,
    missing_entries_skipped: usize,
    non_text_entries_skipped: usize,
    diagnostics: HashSet<SecretScanDiagnostic>,
}

#[derive(Debug, Clone, Default)]
struct TextScanResult {
    keys: HashSet<SecretKey>,
    diagnostics: Vec<SecretScanDiagnostic>,
}

#[derive(Debug, Clone, Default)]
struct SecretScanAccumulator {
    findings: HashMap<SecretKey, MutableSecretFinding>,
}

#[derive(Debug, Clone)]
struct MutableSecretFinding {
    key: SecretKey,
    current: bool,
    history: bool,
    first_seen_commit: String,
    last_seen_commit: String,
    first_seen_commit_index: isize,
    last_seen_commit_index: isize,
}

#[derive(Debug, Clone)]
struct SecretRule {
    name: &'static str,
    confidence: SecretConfidence,
    pattern: Regex,
    secret_group: usize,
    signal_substrings: &'static [&'static str],
}

#[derive(Debug, Clone)]
struct CredentialKeyword {
    signal_substrings: &'static [&'static str],
}

static CREDENTIAL_KEYWORDS: &[CredentialKeyword] = &[
    CredentialKeyword {
        signal_substrings: &["password"],
    },
    CredentialKeyword {
        signal_substrings: &["passwd"],
    },
    CredentialKeyword {
        signal_substrings: &["secret"],
    },
    CredentialKeyword {
        signal_substrings: &["token"],
    },
    CredentialKeyword {
        signal_substrings: &["apikey", "api_key", "api-key"],
    },
    CredentialKeyword {
        signal_substrings: &["clientsecret", "client_secret", "client-secret"],
    },
    CredentialKeyword {
        signal_substrings: &["privatekey", "private_key", "private-key"],
    },
    CredentialKeyword {
        signal_substrings: &["accesskey", "access_key", "access-key"],
    },
];

static HIGH_CONFIDENCE_RULES: LazyLock<Vec<SecretRule>> = LazyLock::new(|| {
    vec![
        SecretRule {
            name: "AWS access key id",
            confidence: SecretConfidence::High,
            pattern: Regex::new(r"\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b").unwrap(),
            secret_group: 0,
            signal_substrings: &["AKIA", "ASIA", "A3T"],
        },
        SecretRule {
            name: "GitHub token",
            confidence: SecretConfidence::High,
            pattern: Regex::new(r"\bgh[opurs]_[A-Za-z0-9_]{36,}\b").unwrap(),
            secret_group: 0,
            signal_substrings: &["gho_", "ghp_", "ghu_", "ghr_", "ghs_"],
        },
        SecretRule {
            name: "Slack token",
            confidence: SecretConfidence::High,
            pattern: Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap(),
            secret_group: 0,
            signal_substrings: &["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"],
        },
        SecretRule {
            name: "Private key block",
            confidence: SecretConfidence::High,
            pattern: Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap(),
            secret_group: 0,
            signal_substrings: &["-----BEGIN "],
        },
        SecretRule {
            name: "JWT",
            confidence: SecretConfidence::High,
            pattern: Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
                .unwrap(),
            secret_group: 0,
            signal_substrings: &["eyJ"],
        },
        SecretRule {
            name: "Google API key",
            confidence: SecretConfidence::High,
            pattern: Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").unwrap(),
            secret_group: 0,
            signal_substrings: &["AIza"],
        },
        SecretRule {
            name: "Stripe key",
            confidence: SecretConfidence::High,
            pattern: Regex::new(r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}\b").unwrap(),
            secret_group: 0,
            signal_substrings: &["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
        },
    ]
});

pub fn report_secret_like_code(
    analyzer: &dyn IAnalyzer,
    params: ReportSecretLikeCodeParams,
) -> ReportSecretLikeCodeResult {
    let findings_cap = if params.max_findings > 0 {
        params.max_findings as usize
    } else {
        DEFAULT_SECRET_MAX_FINDINGS as usize
    };
    let commit_cap = if params.max_commits > 0 {
        params.max_commits as usize
    } else {
        DEFAULT_SECRET_MAX_COMMITS as usize
    };

    let report = match GitContext::open(analyzer.project().root()) {
        Ok(ctx) => scan_repository(
            &ctx,
            commit_cap,
            params.include_history_only,
            params.include_low_confidence,
        ),
        Err(_) => {
            return ReportSecretLikeCodeResult {
                report: "Secret-like code scan requires a JGit-backed repository.".to_string(),
                truncated: false,
                findings: Vec::new(),
                diagnostics: Vec::new(),
            };
        }
    };

    let findings = report.findings.iter().take(findings_cap).cloned().collect();
    ReportSecretLikeCodeResult {
        truncated: report.findings.len() > findings_cap,
        report: format_secret_scan_report(&report, findings_cap),
        findings,
        diagnostics: report.diagnostics.clone(),
    }
}

fn scan_repository(
    ctx: &GitContext,
    commit_cap: usize,
    include_history_only: bool,
    include_low_confidence: bool,
) -> SecretScanReport {
    let ref_info = resolve_default_branch_ref(&ctx.repo);
    let current = scan_default_ref(ctx, &ref_info.ref_name, include_low_confidence);
    let history = scan_history(ctx, commit_cap, include_low_confidence);

    let mut accumulator = SecretScanAccumulator::default();
    let mut diagnostics = current.diagnostics.into_iter().collect::<HashSet<_>>();
    for key in current.keys {
        accumulator.add(key, SecretLocation::Current, "", "", -1);
    }
    for (commit, keys) in &history.keys_by_commit {
        let short_hash = short_hash(commit);
        let commit_index = history.commit_order.get(commit).copied().unwrap_or(-1);
        for key in keys {
            accumulator.add(
                key.clone(),
                SecretLocation::History,
                &short_hash,
                &short_hash,
                commit_index,
            );
        }
    }
    diagnostics.extend(history.diagnostics);

    let mut findings = accumulator.findings();
    findings.retain(|finding| include_history_only || finding.location != SecretLocation::History);
    findings.sort_by(secret_finding_cmp);

    let mut diagnostics = diagnostics.into_iter().collect::<Vec<_>>();
    diagnostics.sort();
    SecretScanReport {
        repository: ctx.repo_root.display().to_string(),
        default_ref_display_name: ref_info.display_name,
        default_ref_fallback: ref_info.fallback,
        max_commits: commit_cap,
        commits_scanned: history.commits_scanned,
        missing_entries_skipped: history.missing_entries_skipped,
        non_text_entries_skipped: history.non_text_entries_skipped,
        findings,
        diagnostics,
    }
}

impl GitContext {
    fn open(project_root: &Path) -> Result<Self, String> {
        let canonical = project_root
            .canonicalize()
            .map_err(|err| format!("cannot canonicalize project root: {err}"))?;
        let repo = Repository::open(&canonical).map_err(|err| {
            format!(
                "not a git repository at project root ({}): {err}",
                canonical.display()
            )
        })?;
        let repo_root = repo
            .workdir()
            .ok_or_else(|| "git repository has no working directory".to_string())?
            .canonicalize()
            .map_err(|err| format!("cannot canonicalize repo root: {err}"))?;
        Ok(Self {
            repo,
            repo_root,
            project_root: canonical,
        })
    }
}

fn scan_default_ref(
    ctx: &GitContext,
    ref_name: &str,
    include_low_confidence: bool,
) -> CurrentScanResult {
    let mut keys = HashSet::new();
    let mut diagnostics = Vec::new();
    let obj = match ctx.repo.revparse_single(ref_name) {
        Ok(obj) => obj,
        Err(_) => return CurrentScanResult::default(),
    };
    let commit = match obj.peel_to_commit() {
        Ok(commit) => commit,
        Err(_) => return CurrentScanResult::default(),
    };
    let tree = match commit.tree() {
        Ok(tree) => tree,
        Err(_) => return CurrentScanResult::default(),
    };
    let _ = tree.walk(TreeWalkMode::PreOrder, |root, entry| {
        if entry.kind() != Some(ObjectType::Blob) {
            return TreeWalkResult::Ok;
        }
        if !is_regular_file_mode(entry.filemode()) {
            return TreeWalkResult::Ok;
        }
        let git_path = if root.is_empty() {
            entry.name().unwrap_or_default().to_string()
        } else {
            format!("{root}{}", entry.name().unwrap_or_default())
        };
        if let Some(project_path) = to_project_relative_path(ctx, &git_path) {
            if test_paths::is_test_like_path(&project_path, language_for_path(&project_path)) {
                return TreeWalkResult::Ok;
            }
            let result =
                scan_blob_content(&ctx.repo, entry.id(), &project_path, include_low_confidence);
            keys.extend(result.keys);
            diagnostics.extend(result.diagnostics);
        }
        TreeWalkResult::Ok
    });
    CurrentScanResult { keys, diagnostics }
}

fn scan_history(
    ctx: &GitContext,
    max_commits: usize,
    include_low_confidence: bool,
) -> HistoryScanAccumulator {
    let mut accumulator = HistoryScanAccumulator::default();
    let mut blob_scan_cache: HashMap<Oid, BlobScanResult> = HashMap::new();
    let mut walker = match ctx.repo.revwalk() {
        Ok(walker) => walker,
        Err(_) => return accumulator,
    };
    if walker
        .set_sorting(Sort::TOPOLOGICAL | Sort::TIME)
        .and_then(|_| walker.push_head())
        .is_err()
    {
        return accumulator;
    }

    for (commit_index, oid_result) in walker.take(max_commits).enumerate() {
        let Ok(oid) = oid_result else {
            continue;
        };
        let Ok(commit) = ctx.repo.find_commit(oid) else {
            continue;
        };
        accumulator.commits_scanned += 1;
        let commit_name = commit.id().to_string();
        accumulator
            .commit_order
            .insert(commit_name.clone(), commit_index as isize);
        let Ok(tree) = commit.tree() else {
            accumulator.missing_entries_skipped += 1;
            continue;
        };
        let _ = tree.walk(TreeWalkMode::PreOrder, |root, entry| {
            if entry.kind() != Some(ObjectType::Blob) {
                return TreeWalkResult::Ok;
            }
            if !is_regular_file_mode(entry.filemode()) {
                return TreeWalkResult::Ok;
            }
            let git_path = if root.is_empty() {
                entry.name().unwrap_or_default().to_string()
            } else {
                format!("{root}{}", entry.name().unwrap_or_default())
            };
            let Some(project_path) = to_project_relative_path(ctx, &git_path) else {
                return TreeWalkResult::Ok;
            };
            if test_paths::is_test_like_path(&project_path, language_for_path(&project_path)) {
                return TreeWalkResult::Ok;
            }
            let oid = entry.id();
            let rebased = if let Some(cached) = blob_scan_cache.get(&oid) {
                rebase_path(&cached.keys, &project_path)
            } else {
                let scanned =
                    scan_blob_content(&ctx.repo, oid, &project_path, include_low_confidence);
                let rebased = scanned.keys.clone();
                blob_scan_cache.insert(
                    oid,
                    BlobScanResult {
                        keys: rebase_path(&scanned.keys, "__cache__"),
                        diagnostics: scanned.diagnostics.clone(),
                        blobs_scanned: scanned.blobs_scanned,
                        missing_entries_skipped: scanned.missing_entries_skipped,
                        non_text_entries_skipped: scanned.non_text_entries_skipped,
                    },
                );
                rebased
            };
            if !rebased.is_empty() {
                accumulator
                    .keys_by_commit
                    .entry(commit_name.clone())
                    .or_default()
                    .extend(rebased);
            }
            let stats = blob_scan_cache.get(&oid).expect("blob cache entry");
            accumulator.blobs_scanned += stats.blobs_scanned;
            accumulator.missing_entries_skipped += stats.missing_entries_skipped;
            accumulator.non_text_entries_skipped += stats.non_text_entries_skipped;
            accumulator
                .diagnostics
                .extend(stats.diagnostics.iter().cloned().map(|mut diagnostic| {
                    diagnostic.path = project_path.clone();
                    diagnostic
                }));
            TreeWalkResult::Ok
        });
    }

    accumulator
}

fn scan_blob_content(
    repo: &Repository,
    oid: Oid,
    path: &str,
    include_low_confidence: bool,
) -> BlobScanResult {
    let Ok(blob) = repo.find_blob(oid) else {
        return BlobScanResult {
            keys: HashSet::new(),
            diagnostics: Vec::new(),
            blobs_scanned: 0,
            missing_entries_skipped: 1,
            non_text_entries_skipped: 0,
        };
    };
    if blob.size() > MAX_BLOB_BYTES {
        return BlobScanResult {
            keys: HashSet::new(),
            diagnostics: Vec::new(),
            blobs_scanned: 0,
            missing_entries_skipped: 0,
            non_text_entries_skipped: 1,
        };
    }
    let Ok(text) = std::str::from_utf8(blob.content()) else {
        return BlobScanResult {
            keys: HashSet::new(),
            diagnostics: Vec::new(),
            blobs_scanned: 0,
            missing_entries_skipped: 0,
            non_text_entries_skipped: 1,
        };
    };
    if is_binary_text(text) {
        return BlobScanResult {
            keys: HashSet::new(),
            diagnostics: Vec::new(),
            blobs_scanned: 0,
            missing_entries_skipped: 0,
            non_text_entries_skipped: 1,
        };
    }
    let scanned = scan_text_detailed(path, text, include_low_confidence);
    BlobScanResult {
        keys: scanned.keys,
        diagnostics: scanned.diagnostics,
        blobs_scanned: 1,
        missing_entries_skipped: 0,
        non_text_entries_skipped: 0,
    }
}

#[cfg(test)]
fn scan_text(path: &str, text: &str, include_low_confidence: bool) -> HashSet<SecretKey> {
    scan_text_detailed(path, text, include_low_confidence).keys
}

fn scan_text_detailed(path: &str, text: &str, include_low_confidence: bool) -> TextScanResult {
    let mut result = TextScanResult::default();
    let mut line_start = 0;
    for (idx, line_with_ending) in text.split_inclusive('\n').enumerate() {
        let line = line_with_ending
            .strip_suffix('\n')
            .unwrap_or(line_with_ending);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let line_number = idx + 1;
        for rule in HIGH_CONFIDENCE_RULES.iter() {
            if !rule
                .signal_substrings
                .iter()
                .any(|signal| line.contains(signal))
            {
                continue;
            }
            for captures in rule.pattern.captures_iter(line) {
                let Some(matched) = captures.get(rule.secret_group) else {
                    continue;
                };
                let value = matched.as_str();
                if is_placeholder(value) {
                    continue;
                }
                let start = line_start + matched.start();
                let end = line_start + matched.end();
                result.keys.insert(SecretKey {
                    path: path.to_string(),
                    line: line_number,
                    rule: rule.name.to_string(),
                    confidence: rule.confidence,
                    sample: redacted_line(line, value, matched.start(), matched.end()),
                    redaction_span: redaction_span(text, start, end),
                });
            }
        }
        line_start += line_with_ending.len();
    }
    add_structural_assignment_findings(&mut result, path, text, include_low_confidence);
    result
}

fn add_structural_assignment_findings(
    result: &mut TextScanResult,
    path: &str,
    text: &str,
    include_low_confidence: bool,
) {
    if !has_credential_keyword(&text.to_lowercase()) {
        return;
    }
    let path_obj = Path::new(path);
    let language = language_for_path(path);
    let grammar = parser_language_for_path(language, path_obj).or_else(|| {
        match path_obj
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "yaml" | "yml" => Some(tree_sitter_yaml::LANGUAGE.into()),
            "json" => Some(tree_sitter_json::LANGUAGE.into()),
            "properties" => Some(tree_sitter_properties::LANGUAGE.into()),
            _ => None,
        }
    });
    let Some(grammar) = grammar else {
        result.diagnostics.push(SecretScanDiagnostic {
            path: path.to_string(),
            kind: SecretScanDiagnosticKind::UnsupportedAssignmentSyntax,
        });
        return;
    };
    let mut parser = Parser::new();
    if parser.set_language(&grammar).is_err() {
        result.diagnostics.push(SecretScanDiagnostic {
            path: path.to_string(),
            kind: SecretScanDiagnosticKind::UnsupportedAssignmentSyntax,
        });
        return;
    }
    let Some(tree) = parser.parse(text, None) else {
        result.diagnostics.push(SecretScanDiagnostic {
            path: path.to_string(),
            kind: SecretScanDiagnosticKind::UnparseableAssignmentSyntax,
        });
        return;
    };
    if tree.root_node().has_error() {
        result.diagnostics.push(SecretScanDiagnostic {
            path: path.to_string(),
            kind: SecretScanDiagnosticKind::UnparseableAssignmentSyntax,
        });
    }

    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
        let Some((name, value)) = assignment_parts(node) else {
            continue;
        };
        let Ok(name_text) = name.utf8_text(text.as_bytes()) else {
            continue;
        };
        if !has_credential_keyword(&name_text.to_lowercase()) {
            continue;
        }
        let Some(literal) = literal_value_node(value) else {
            continue;
        };
        if literal.start_position().row != literal.end_position().row
            || contains_descendant_kind(literal, "escape_sequence")
        {
            continue;
        }
        let Some((start, end)) = literal_content_range(literal, text) else {
            continue;
        };
        let value_text = &text[start..end];
        let confidence = if value_text.chars().count() >= 12 {
            SecretConfidence::Medium
        } else if include_low_confidence {
            SecretConfidence::Low
        } else {
            continue;
        };
        if !is_plausible_assignment_secret(value_text, confidence) {
            continue;
        }
        let span = redaction_span(text, start, end);
        result.keys.insert(SecretKey {
            path: path.to_string(),
            line: span.start_line,
            rule: if confidence == SecretConfidence::Low {
                "Credential-like name".to_string()
            } else {
                "Credential assignment".to_string()
            },
            confidence,
            sample: redact_assignment_excerpt(text, node, start, end),
            redaction_span: span,
        });
    }
}

fn assignment_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    match node.kind() {
        "assignment_expression" | "assignment" | "short_var_declaration" => Some((
            node.child_by_field_name("left")?,
            node.child_by_field_name("right")?,
        )),
        "variable_declarator" | "var_spec" => Some((
            node.child_by_field_name("name")?,
            node.child_by_field_name("value")?,
        )),
        "let_declaration" => Some((
            node.child_by_field_name("pattern")?,
            node.child_by_field_name("value")?,
        )),
        "const_item" | "static_item" => Some((
            node.child_by_field_name("name")?,
            node.child_by_field_name("value")?,
        )),
        "pair" | "block_mapping_pair" | "flow_pair" => Some((
            node.child_by_field_name("key")?,
            node.child_by_field_name("value")?,
        )),
        "property" => {
            let mut cursor = node.walk();
            let mut children = node.named_children(&mut cursor);
            Some((children.next()?, children.next()?))
        }
        _ => None,
    }
}

fn literal_value_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if matches!(
            node.kind(),
            "string_literal"
                | "string"
                | "template_string"
                | "interpreted_string_literal"
                | "raw_string_literal"
                | "double_quote_scalar"
                | "single_quote_scalar"
                | "plain_scalar"
                | "block_scalar"
                | "value"
        ) {
            if node.kind() == "template_string"
                && (0..node.named_child_count())
                    .filter_map(|index| node.named_child(index))
                    .any(|child| child.kind() == "template_substitution")
            {
                return None;
            }
            return Some(node);
        }
        if !matches!(
            node.kind(),
            "flow_node" | "block_node" | "equals_value_clause" | "parenthesized_expression"
        ) || node.named_child_count() != 1
        {
            return None;
        }
        node = node.named_child(0)?;
    }
}

fn literal_content_range(node: Node<'_>, text: &str) -> Option<(usize, usize)> {
    let mut start = node.start_byte();
    let mut end = node.end_byte();
    let bytes = text.as_bytes().get(start..end)?;
    if matches!(
        node.kind(),
        "string_literal"
            | "string"
            | "template_string"
            | "double_quote_scalar"
            | "single_quote_scalar"
    ) && bytes.len() >= 2
        && matches!(
            (bytes[0], bytes[bytes.len() - 1]),
            (b'\'', b'\'') | (b'"', b'"') | (b'`', b'`')
        )
    {
        start += 1;
        end -= 1;
    }
    (start < end).then_some((start, end))
}

fn contains_descendant_kind(node: Node<'_>, kind: &str) -> bool {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current != node && current.kind() == kind {
            return true;
        }
        let mut cursor = current.walk();
        pending.extend(current.named_children(&mut cursor));
    }
    false
}

fn redaction_span(text: &str, start: usize, end: usize) -> SecretRedactionSpan {
    let start_point = point_for_offset(text, start);
    let end_point = point_for_offset(text, end);
    SecretRedactionSpan {
        start_byte: start,
        end_byte: end,
        start_line: start_point.0,
        start_column: start_point.1,
        end_line: end_point.0,
        end_column: end_point.1,
    }
}

fn point_for_offset(text: &str, offset: usize) -> (usize, usize) {
    let prefix = &text[..offset.min(text.len())];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix.len(), |(_, tail)| tail.len())
        + 1;
    (line, column)
}

fn redact_assignment_excerpt(text: &str, assignment: Node<'_>, start: usize, end: usize) -> String {
    let excerpt_start = assignment.start_byte();
    let excerpt_end = assignment.end_byte().min(text.len());
    let mut excerpt = text[excerpt_start..excerpt_end].to_string();
    let relative_start = start - excerpt_start;
    let relative_end = end - excerpt_start;
    excerpt.replace_range(
        relative_start..relative_end,
        &redact_secret(&text[start..end]),
    );
    if excerpt.len() > MAX_EXCERPT_CHARS {
        format!("{}...", &excerpt[..MAX_EXCERPT_CHARS - 3])
    } else {
        excerpt.trim().to_string()
    }
}

fn has_credential_keyword(lower_line: &str) -> bool {
    CREDENTIAL_KEYWORDS.iter().any(|keyword| {
        keyword
            .signal_substrings
            .iter()
            .any(|signal| lower_line.contains(signal))
    })
}

fn is_plausible_assignment_secret(value: &str, confidence: SecretConfidence) -> bool {
    if is_placeholder(value) {
        return false;
    }
    match confidence {
        SecretConfidence::Low => value.len() >= 4,
        _ => value.len() >= 12 && approximate_entropy(value) >= 3.0,
    }
}

fn is_placeholder(value: &str) -> bool {
    let stripped = value.trim();
    if stripped.is_empty() || stripped.starts_with("${") || stripped.starts_with('<') {
        return true;
    }
    let lower = stripped.to_lowercase();
    PLACEHOLDER_VALUES.contains(&lower.as_str()) || lower.chars().collect::<HashSet<_>>().len() <= 2
}

fn approximate_entropy(value: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    for ch in value.chars() {
        *counts.entry(ch).or_default() += 1;
    }
    let length = value.chars().count() as f64;
    counts
        .values()
        .map(|count| {
            let p = *count as f64 / length;
            -p * p.log2()
        })
        .sum()
}

fn redacted_line(line: &str, secret: &str, start: usize, end: usize) -> String {
    let redacted = redact_secret(secret);
    let start = start.min(line.len());
    let end = end.min(line.len());
    let excerpt = line[start..end].replace(secret, &redacted);
    if excerpt.len() > MAX_EXCERPT_CHARS {
        format!("{}...", &excerpt[..MAX_EXCERPT_CHARS - 3])
    } else {
        excerpt.trim().to_string()
    }
}

fn redact_secret(secret: &str) -> String {
    if secret.len() <= 8 {
        return "[REDACTED]".to_string();
    }
    let visible = 4.min(MAX_SECRET_SAMPLE_VALUE_CHARS / 2);
    format!(
        "{}...{}",
        &secret[..visible],
        &secret[secret.len() - visible..]
    )
}

fn to_project_relative_path(ctx: &GitContext, git_path: &str) -> Option<String> {
    let repo_rel = PathBuf::from(normalize_pattern(git_path));
    let project_prefix = ctx
        .project_root
        .strip_prefix(&ctx.repo_root)
        .ok()
        .filter(|prefix| !prefix.as_os_str().is_empty())
        .map(normalize_path)
        .unwrap_or_default();
    let normalized_repo_rel = normalize_path(&repo_rel);
    if !project_prefix.as_os_str().is_empty() && !normalized_repo_rel.starts_with(&project_prefix) {
        return None;
    }
    let project_rel = if project_prefix.as_os_str().is_empty() {
        normalized_repo_rel
    } else {
        normalized_repo_rel
            .strip_prefix(&project_prefix)
            .ok()?
            .to_path_buf()
    };
    Some(project_rel.to_string_lossy().replace('\\', "/"))
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => out.push(part),
            std::path::Component::CurDir => {}
            _ => return PathBuf::new(),
        }
    }
    out
}

fn language_for_path(path: &str) -> Language {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

fn is_regular_file_mode(mode: i32) -> bool {
    mode == i32::from(FileMode::Blob) || mode == i32::from(FileMode::BlobExecutable)
}

fn is_binary_text(text: &str) -> bool {
    text.chars()
        .any(|ch| ch == '\0' || (ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t'))
}

fn rebase_path(keys: &HashSet<SecretKey>, path: &str) -> HashSet<SecretKey> {
    keys.iter()
        .map(|key| SecretKey {
            path: path.to_string(),
            line: key.line,
            rule: key.rule.clone(),
            confidence: key.confidence,
            sample: key.sample.clone(),
            redaction_span: key.redaction_span.clone(),
        })
        .collect()
}

impl SecretScanAccumulator {
    fn add(
        &mut self,
        key: SecretKey,
        location: SecretLocation,
        first_seen: &str,
        last_seen: &str,
        commit_index: isize,
    ) {
        self.findings
            .entry(key.clone())
            .or_insert_with(|| MutableSecretFinding {
                key,
                current: false,
                history: false,
                first_seen_commit: String::new(),
                last_seen_commit: String::new(),
                first_seen_commit_index: isize::MIN,
                last_seen_commit_index: isize::MAX,
            })
            .add(location, first_seen, last_seen, commit_index);
    }

    fn findings(self) -> Vec<SecretFinding> {
        self.findings
            .into_values()
            .map(MutableSecretFinding::into_finding)
            .collect()
    }
}

impl MutableSecretFinding {
    fn add(
        &mut self,
        location: SecretLocation,
        first_seen: &str,
        last_seen: &str,
        commit_index: isize,
    ) {
        if location == SecretLocation::Current {
            self.current = true;
            return;
        }
        self.history = true;
        if commit_index < 0 {
            return;
        }
        if !first_seen.is_empty() && commit_index > self.first_seen_commit_index {
            self.first_seen_commit = first_seen.to_string();
            self.first_seen_commit_index = commit_index;
        }
        if !last_seen.is_empty() && commit_index < self.last_seen_commit_index {
            self.last_seen_commit = last_seen.to_string();
            self.last_seen_commit_index = commit_index;
        }
    }

    fn into_finding(self) -> SecretFinding {
        let location = match (self.current, self.history) {
            (true, true) => SecretLocation::Both,
            (true, false) => SecretLocation::Current,
            (false, true) => SecretLocation::History,
            (false, false) => SecretLocation::History,
        };
        SecretFinding {
            path: self.key.path,
            line: self.key.line,
            rule: self.key.rule,
            confidence: self.key.confidence,
            location,
            first_seen_commit: self.first_seen_commit,
            last_seen_commit: self.last_seen_commit,
            sample: self.key.sample,
            redaction_span: self.key.redaction_span,
        }
    }
}

fn short_hash(commit: &str) -> String {
    commit.chars().take(7).collect()
}

fn secret_finding_cmp(left: &SecretFinding, right: &SecretFinding) -> Ordering {
    location_rank(left.location)
        .cmp(&location_rank(right.location))
        .then_with(|| confidence_rank(left.confidence).cmp(&confidence_rank(right.confidence)))
        .then_with(|| left.path.cmp(&right.path))
        .then_with(|| left.line.cmp(&right.line))
        .then_with(|| left.rule.cmp(&right.rule))
}

fn location_rank(location: SecretLocation) -> u8 {
    match location {
        SecretLocation::Both => 0,
        SecretLocation::Current => 1,
        SecretLocation::History => 2,
    }
}

fn confidence_rank(confidence: SecretConfidence) -> u8 {
    match confidence {
        SecretConfidence::High => 0,
        SecretConfidence::Medium => 1,
        SecretConfidence::Low => 2,
    }
}

fn location_label(location: SecretLocation) -> &'static str {
    match location {
        SecretLocation::Current => "CURRENT",
        SecretLocation::History => "HISTORY",
        SecretLocation::Both => "BOTH",
    }
}

fn confidence_label(confidence: SecretConfidence) -> &'static str {
    match confidence {
        SecretConfidence::High => "HIGH",
        SecretConfidence::Medium => "MEDIUM",
        SecretConfidence::Low => "LOW",
    }
}

fn diagnostic_label(kind: SecretScanDiagnosticKind) -> &'static str {
    match kind {
        SecretScanDiagnosticKind::UnsupportedAssignmentSyntax => "unsupported assignment syntax",
        SecretScanDiagnosticKind::UnparseableAssignmentSyntax => "unparseable assignment syntax",
    }
}

fn format_secret_scan_report(report: &SecretScanReport, max_findings: usize) -> String {
    let shown = report
        .findings
        .iter()
        .take(max_findings)
        .collect::<Vec<_>>();
    let truncated = report.findings.len() > shown.len();
    let mut lines = ReportLines::new();
    lines.line("## brokk-secret-scan");
    lines.blank();
    lines.line(format!(
        "- Repository: `{}`",
        sanitize_table_cell(&report.repository)
    ));
    lines.line(format!(
        "- Current/default ref scanned: `{}`",
        sanitize_table_cell(&report.default_ref_display_name)
    ));
    if report.default_ref_fallback {
        lines.line("- Note: default branch could not be determined; fell back to `HEAD`.");
    }
    lines.line(format!(
        "- History commits scanned: {} (cap {})",
        report.commits_scanned, report.max_commits
    ));
    lines.line(format!(
        "- Missing git entries skipped: {}",
        report.missing_entries_skipped
    ));
    lines.line(format!(
        "- Non-text or oversized blobs skipped: {}",
        report.non_text_entries_skipped
    ));
    lines.line(format!(
        "- Assignment syntax diagnostics: {}",
        report.diagnostics.len()
    ));
    lines.line(format!(
        "- Findings shown: {} of {}{}",
        shown.len(),
        report.findings.len(),
        if truncated { " (truncated)" } else { "" }
    ));
    lines.blank();

    if !report.diagnostics.is_empty() {
        lines.line("### Incomplete assignment classification");
        lines.blank();
        for diagnostic in &report.diagnostics {
            lines.line(format!(
                "- `{}`: {}",
                sanitize_table_cell(&diagnostic.path),
                diagnostic_label(diagnostic.kind)
            ));
        }
        lines.blank();
    }

    if shown.is_empty() {
        if report.diagnostics.is_empty() {
            lines.line("No secret-like code found.");
        } else {
            lines.line(
                "No secret-like findings retained; assignment classification was incomplete.",
            );
        }
        return lines.build();
    }

    lines.line(
        "| Location | Confidence | Rule | File:Line | First Seen | Last Seen | Redacted Excerpt |",
    );
    lines.line(
        "|----------|------------|------|-----------|------------|-----------|------------------|",
    );
    for finding in shown {
        let first_seen = if finding.first_seen_commit.is_empty() {
            "-".to_string()
        } else {
            finding.first_seen_commit.clone()
        };
        let last_seen = if finding.last_seen_commit.is_empty() {
            "-".to_string()
        } else {
            finding.last_seen_commit.clone()
        };
        lines.line(format!(
            "| {} | {} | `{}` | `{}:{}` | `{}` | `{}` | `{}` |",
            location_label(finding.location),
            confidence_label(finding.confidence),
            sanitize_table_cell(&finding.rule),
            sanitize_table_cell(&finding.path),
            finding.line,
            first_seen,
            last_seen,
            sanitize_table_cell(&finding.sample)
        ));
    }
    lines.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerConfig, WorkspaceAnalyzer};
    use git2::{IndexAddOption, Signature};
    use std::fs;
    use tempfile::TempDir;

    fn init_repo() -> (TempDir, Repository) {
        let temp = TempDir::new().unwrap();
        let repo = Repository::init(temp.path()).unwrap();
        (temp, repo)
    }

    fn build_analyzer(root: &Path) -> WorkspaceAnalyzer {
        let project = crate::TestProject::from_root_with_inferred_languages(root.to_path_buf())
            .unwrap_or_else(|_| crate::TestProject::new(root.to_path_buf(), crate::Language::Java));
        WorkspaceAnalyzer::build_ephemeral_footgun(
            std::sync::Arc::new(project),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build")
    }

    fn write_file(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    fn commit_all(repo: &Repository, message: &str) {
        let mut index = repo.index().unwrap();
        index
            .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
            .unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let sig = Signature::now("Tester", "test@example.com").unwrap();
        let parents = repo
            .head()
            .ok()
            .and_then(|head| head.target())
            .and_then(|oid| repo.find_commit(oid).ok())
            .map(|commit| vec![commit])
            .unwrap_or_default();
        let parent_refs = parents.iter().collect::<Vec<_>>();
        repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parent_refs)
            .unwrap();
        let origin_head = repo.reference_symbolic(
            "refs/remotes/origin/HEAD",
            "refs/heads/master",
            true,
            "set remote default",
        );
        if origin_head.is_err() {
            let _ = repo.reference_symbolic(
                "refs/remotes/origin/HEAD",
                "refs/heads/main",
                true,
                "set remote default",
            );
        }
    }

    #[test]
    fn scan_text_redacts_high_confidence_matches() {
        let findings = scan_text(
            "config/app.properties",
            "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
            false,
        );
        let finding = findings.iter().next().unwrap();
        assert!(!finding.sample.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(finding.sample.contains("AKIA"));
    }

    #[test]
    fn matcher_detects_provider_tokens_and_private_keys() {
        let text = r#"
        aws = "AKIAIOSFODNN7EXAMPLE"
        token = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        key = "-----BEGIN RSA PRIVATE KEY-----"
        "#;

        let findings = scan_text("Secrets.java", text, false);

        assert!(findings.iter().any(|f| f.rule == "AWS access key id"));
        assert!(findings.iter().any(|f| f.rule == "GitHub token"));
        assert!(findings.iter().any(|f| f.rule == "Private key block"));
    }

    #[test]
    fn matcher_detects_provider_tokens_without_credential_keywords() {
        let text = r#"
        value = "AKIAIOSFODNN7EXAMPLE"
        value = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        value = "xoxb-1234567890-abcedfghij"
        value = "AIza12345678901234567890123456789012345"
        value = "sk_live_1234567890abcdef"
        "#;

        let findings = scan_text("Config.java", text, false);

        assert!(findings.iter().any(|f| f.rule == "AWS access key id"));
        assert!(findings.iter().any(|f| f.rule == "GitHub token"));
        assert!(findings.iter().any(|f| f.rule == "Slack token"));
        assert!(findings.iter().any(|f| f.rule == "Google API key"));
        assert!(findings.iter().any(|f| f.rule == "Stripe key"));
    }

    #[test]
    fn matcher_detects_generic_credential_assignment() {
        let findings = scan_text("config.yml", "client_secret: qQ9xV7pL2mN8rT4sZ6wY", false);
        assert!(findings.iter().any(|f| f.rule == "Credential assignment"));
    }

    #[test]
    fn matcher_ignores_nonliteral_credential_assignments() {
        let java = "this.promptTokensDetails = builder.promptTokensDetails;";
        let typescript = "tokenizeBody = makeEditBlockBodyTokenizer(parser, state);";

        assert!(scan_text("Usage.java", java, false).is_empty());
        assert!(scan_text("fenced-edit-block.ts", typescript, false).is_empty());
    }

    #[test]
    fn matcher_reports_structured_redaction_spans_without_values() {
        let text = "const clientSecret = \"qQ9xV7pL2mN8rT4sZ6wY\";";
        let finding = scan_text("config.ts", text, false)
            .into_iter()
            .find(|finding| finding.rule == "Credential assignment")
            .unwrap();

        assert_eq!(
            &text[finding.redaction_span.start_byte..finding.redaction_span.end_byte],
            "qQ9xV7pL2mN8rT4sZ6wY"
        );
        assert_eq!(finding.redaction_span.start_line, 1);
        assert!(!finding.sample.contains("qQ9xV7pL2mN8rT4sZ6wY"));
    }

    #[test]
    fn matcher_treats_escaped_and_multiline_literals_as_near_misses() {
        let escaped = r#"const apiKey = "qQ9xV7pL2mN8rT4s\\\"Z6wY";"#;
        let multiline = "const accessToken = `qQ9xV7pL2mN8rT4s\nZ6wY`;";

        assert!(scan_text("config.ts", escaped, false).is_empty());
        assert!(scan_text("config.ts", multiline, false).is_empty());
    }

    #[test]
    fn unsupported_assignment_syntax_is_diagnostic() {
        let result = scan_text_detailed(
            "config.unknown",
            "client_secret = qQ9xV7pL2mN8rT4sZ6wY",
            false,
        );

        assert!(result.keys.is_empty());
        assert_eq!(
            result.diagnostics,
            vec![SecretScanDiagnostic {
                path: "config.unknown".to_string(),
                kind: SecretScanDiagnosticKind::UnsupportedAssignmentSyntax,
            }]
        );
    }

    #[test]
    fn matcher_detects_credential_assignment_keyword_variants() {
        let text = r#"apiKey: "qQ9xV7pL2mN8rT4sZ6wY"
api_key: "aB9xV7pL2mN8rT4sZ6wY"
api-key: "zZ9xV7pL2mN8rT4sZ6wY"
access_key: "mM9xV7pL2mN8rT4sZ6wY"
"#;

        let findings = scan_text("config.yml", text, false);
        assert_eq!(
            4,
            findings
                .iter()
                .filter(|f| f.rule == "Credential assignment")
                .count()
        );
    }

    #[test]
    fn matcher_ignores_placeholders_and_low_confidence_unless_requested() {
        let text = r#"password: "changeme"
api_key: "test"
token: "abcd123"
"#;

        let normal_findings = scan_text("config.yml", text, false);
        let low_findings = scan_text("config.yml", text, true);

        assert!(normal_findings.is_empty(), "{normal_findings:?}");
        assert_eq!(
            low_findings
                .iter()
                .filter(|f| f.rule == "Credential-like name")
                .count(),
            1,
            "{low_findings:?}"
        );
    }

    #[test]
    fn low_confidence_assignment_is_gated() {
        let path = "config.yml";
        let text = "client_secret: shorty";
        assert!(scan_text(path, text, false).is_empty());
        assert!(!scan_text(path, text, true).is_empty());
    }

    #[test]
    fn secret_report_skips_test_paths_and_redacts_output() {
        let (temp, repo) = init_repo();
        write_file(
            temp.path(),
            "src/main/resources/app.properties",
            "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        );
        write_file(
            temp.path(),
            "src/test/java/AppTest.java",
            "String token = \"ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIK\";\n",
        );
        commit_all(&repo, "seed secrets");
        let analyzer = build_analyzer(temp.path());

        let result = report_secret_like_code(
            analyzer.analyzer(),
            ReportSecretLikeCodeParams {
                max_findings: 20,
                max_commits: 20,
                include_history_only: true,
                include_low_confidence: false,
            },
        );

        assert!(result.report.contains("src/main/resources/app.properties"));
        assert!(!result.report.contains("src/test/java/AppTest.java"));
        assert!(
            !result
                .report
                .contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        );
        assert!(!result.findings.is_empty());
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
    }

    #[test]
    fn tool_reports_current_and_history_findings_and_excludes_tests() {
        let (temp, repo) = init_repo();
        write_file(
            temp.path(),
            "src/main/java/App.java",
            r#"class App { String client_secret = "qQ9xV7pL2mN8rT4sZ6wY"; }"#,
        );
        write_file(
            temp.path(),
            "src/test/java/AppTest.java",
            r#"class AppTest { String token = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"; }"#,
        );
        commit_all(&repo, "add current secret");

        write_file(
            temp.path(),
            "src/main/java/App.java",
            r#"class App { String value = "clean"; }"#,
        );
        commit_all(&repo, "remove current secret");

        write_file(
            temp.path(),
            "src/main/java/Live.java",
            r#"class Live { String token = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIK"; }"#,
        );
        commit_all(&repo, "add live secret");
        let analyzer = build_analyzer(temp.path());

        let result = report_secret_like_code(
            analyzer.analyzer(),
            ReportSecretLikeCodeParams {
                max_findings: 20,
                max_commits: 20,
                include_history_only: true,
                include_low_confidence: false,
            },
        );

        assert!(result.report.contains("HISTORY"), "{}", result.report);
        assert!(
            result.report.contains("CURRENT") || result.report.contains("BOTH"),
            "{}",
            result.report
        );
        assert!(result.report.contains("src/main/java/App.java"));
        assert!(result.report.contains("src/main/java/Live.java"));
        assert!(!result.report.contains("src/test/java/AppTest.java"));
        assert!(!result.report.contains("qQ9xV7pL2mN8rT4sZ6wY"));
    }

    #[test]
    fn tool_reports_cached_duplicate_blob_at_each_path() {
        let (temp, repo) = init_repo();
        let text = "client_secret: qQ9xV7pL2mN8rT4sZ6wY";
        write_file(temp.path(), "src/main/resources/first.yml", text);
        write_file(temp.path(), "src/main/resources/second.yml", text);
        commit_all(&repo, "add duplicate blob secrets");
        let analyzer = build_analyzer(temp.path());

        let result = report_secret_like_code(
            analyzer.analyzer(),
            ReportSecretLikeCodeParams {
                max_findings: 20,
                max_commits: 5,
                include_history_only: false,
                include_low_confidence: false,
            },
        );

        assert!(
            result.report.contains("src/main/resources/first.yml"),
            "{}",
            result.report
        );
        assert!(
            result.report.contains("src/main/resources/second.yml"),
            "{}",
            result.report
        );
    }

    #[test]
    fn history_scan_keeps_findings_across_commits_with_duplicate_blobs() {
        let (temp, repo) = init_repo();
        write_file(
            temp.path(),
            "src/main/resources/early.yml",
            "client_secret: qQ9xV7pL2mN8rT4sZ6wY",
        );
        commit_all(&repo, "add early secret");

        write_file(
            temp.path(),
            "src/main/resources/duplicate-one.yml",
            "client_secret: aA9xV7pL2mN8rT4sZ6wY",
        );
        write_file(
            temp.path(),
            "src/main/resources/duplicate-two.yml",
            "client_secret: aA9xV7pL2mN8rT4sZ6wY",
        );
        write_file(
            temp.path(),
            "src/main/resources/middle.yml",
            "client_secret: bB9xV7pL2mN8rT4sZ6wY",
        );
        commit_all(&repo, "add duplicate and middle secrets");

        write_file(
            temp.path(),
            "src/main/resources/late.yml",
            "client_secret: cC9xV7pL2mN8rT4sZ6wY",
        );
        commit_all(&repo, "add late secret");
        let analyzer = build_analyzer(temp.path());

        let result = report_secret_like_code(
            analyzer.analyzer(),
            ReportSecretLikeCodeParams {
                max_findings: 50,
                max_commits: 20,
                include_history_only: true,
                include_low_confidence: false,
            },
        );

        for path in [
            "src/main/resources/early.yml",
            "src/main/resources/middle.yml",
            "src/main/resources/late.yml",
            "src/main/resources/duplicate-one.yml",
            "src/main/resources/duplicate-two.yml",
        ] {
            assert!(
                result.report.contains(path),
                "missing {path} in {}",
                result.report
            );
        }
    }
}
