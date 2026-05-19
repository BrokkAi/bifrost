//! MCP `report_secret_like_code` handler. Ports brokk's git-backed
//! secret scanner and the brokk-core MCP wrapper to bifrost.

use super::{ReportLines, sanitize_table_cell};
use crate::analyzer::IAnalyzer;
use crate::path_utils::normalize_pattern;
use git2::{FileMode, ObjectType, Oid, Repository, Sort, TreeWalkMode, TreeWalkResult};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SecretKey {
    path: String,
    line: usize,
    rule: String,
    confidence: SecretConfidence,
    sample: String,
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
}

struct GitContext {
    repo: Repository,
    repo_root: PathBuf,
    project_root: PathBuf,
}

#[derive(Debug, Clone)]
struct DefaultRefInfo {
    ref_name: String,
    display_name: String,
    fallback: bool,
}

#[derive(Debug, Clone)]
struct BlobScanResult {
    keys: HashSet<SecretKey>,
    blobs_scanned: usize,
    missing_entries_skipped: usize,
    non_text_entries_skipped: usize,
}

#[derive(Debug, Clone, Default)]
struct CurrentScanResult {
    keys: HashSet<SecretKey>,
}

#[derive(Debug, Clone, Default)]
struct HistoryScanAccumulator {
    keys_by_commit: HashMap<String, HashSet<SecretKey>>,
    commit_order: HashMap<String, isize>,
    commits_scanned: usize,
    blobs_scanned: usize,
    missing_entries_skipped: usize,
    non_text_entries_skipped: usize,
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
    pattern_fragment: &'static str,
    signal_substrings: &'static [&'static str],
}

static CREDENTIAL_KEYWORDS: &[CredentialKeyword] = &[
    CredentialKeyword {
        pattern_fragment: "password",
        signal_substrings: &["password"],
    },
    CredentialKeyword {
        pattern_fragment: "passwd",
        signal_substrings: &["passwd"],
    },
    CredentialKeyword {
        pattern_fragment: "secret",
        signal_substrings: &["secret"],
    },
    CredentialKeyword {
        pattern_fragment: "token",
        signal_substrings: &["token"],
    },
    CredentialKeyword {
        pattern_fragment: "api[_-]?key",
        signal_substrings: &["apikey", "api_key", "api-key"],
    },
    CredentialKeyword {
        pattern_fragment: "client[_-]?secret",
        signal_substrings: &["clientsecret", "client_secret", "client-secret"],
    },
    CredentialKeyword {
        pattern_fragment: "private[_-]?key",
        signal_substrings: &["privatekey", "private_key", "private-key"],
    },
    CredentialKeyword {
        pattern_fragment: "access[_-]?key",
        signal_substrings: &["accesskey", "access_key", "access-key"],
    },
];

static CREDENTIAL_NAME_PATTERN_FRAGMENT: LazyLock<String> = LazyLock::new(|| {
    CREDENTIAL_KEYWORDS
        .iter()
        .map(|k| k.pattern_fragment)
        .collect::<Vec<_>>()
        .join("|")
});

static ASSIGNMENT_SECRET_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        "(?i)([A-Za-z0-9_.-]*(?:{})[A-Za-z0-9_.-]*)\\s*[:=]\\s*['\"]?([^'\"\\s,;#}}]+)",
        *CREDENTIAL_NAME_PATTERN_FRAGMENT
    ))
    .expect("valid assignment secret regex")
});

static LOW_CONFIDENCE_SECRET_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        "(?i)([A-Za-z0-9_.-]*(?:{})[A-Za-z0-9_.-]*)\\s*[:=]\\s*['\"]?([^'\"\\s,;#}}]{{4,11}})",
        *CREDENTIAL_NAME_PATTERN_FRAGMENT
    ))
    .expect("valid low-confidence secret regex")
});

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
            };
        }
    };

    ReportSecretLikeCodeResult {
        truncated: report.findings.len() > findings_cap,
        report: format_secret_scan_report(&report, findings_cap),
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

    let mut findings = accumulator.findings();
    findings.retain(|finding| include_history_only || finding.location != SecretLocation::History);
    findings.sort_by(secret_finding_cmp);

    SecretScanReport {
        repository: ctx.repo_root.display().to_string(),
        default_ref_display_name: ref_info.display_name,
        default_ref_fallback: ref_info.fallback,
        max_commits: commit_cap,
        commits_scanned: history.commits_scanned,
        missing_entries_skipped: history.missing_entries_skipped,
        non_text_entries_skipped: history.non_text_entries_skipped,
        findings,
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

fn resolve_default_branch_ref(repo: &Repository) -> DefaultRefInfo {
    if let Ok(head_ref) = repo.find_reference("refs/remotes/origin/HEAD")
        && let Some(target) = head_ref.symbolic_target()
    {
        let display = target.rsplit('/').next().unwrap_or(target).to_string();
        return DefaultRefInfo {
            ref_name: target.to_string(),
            display_name: display,
            fallback: false,
        };
    }
    DefaultRefInfo {
        ref_name: "HEAD".to_string(),
        display_name: "HEAD (default branch unavailable)".to_string(),
        fallback: true,
    }
}

fn scan_default_ref(
    ctx: &GitContext,
    ref_name: &str,
    include_low_confidence: bool,
) -> CurrentScanResult {
    let mut keys = HashSet::new();
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
            if looks_like_test_path(&project_path) {
                return TreeWalkResult::Ok;
            }
            let result =
                scan_blob_content(&ctx.repo, entry.id(), &project_path, include_low_confidence);
            keys.extend(result.keys);
        }
        TreeWalkResult::Ok
    });
    CurrentScanResult { keys }
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
            if looks_like_test_path(&project_path) {
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
            blobs_scanned: 0,
            missing_entries_skipped: 1,
            non_text_entries_skipped: 0,
        };
    };
    if blob.size() > MAX_BLOB_BYTES {
        return BlobScanResult {
            keys: HashSet::new(),
            blobs_scanned: 0,
            missing_entries_skipped: 0,
            non_text_entries_skipped: 1,
        };
    }
    let Ok(text) = std::str::from_utf8(blob.content()) else {
        return BlobScanResult {
            keys: HashSet::new(),
            blobs_scanned: 0,
            missing_entries_skipped: 0,
            non_text_entries_skipped: 1,
        };
    };
    if is_binary_text(text) {
        return BlobScanResult {
            keys: HashSet::new(),
            blobs_scanned: 0,
            missing_entries_skipped: 0,
            non_text_entries_skipped: 1,
        };
    }
    BlobScanResult {
        keys: scan_text(path, text, include_low_confidence),
        blobs_scanned: 1,
        missing_entries_skipped: 0,
        non_text_entries_skipped: 0,
    }
}

fn scan_text(path: &str, text: &str, include_low_confidence: bool) -> HashSet<SecretKey> {
    let mut findings = HashSet::new();
    for (idx, line) in text.lines().enumerate() {
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
                findings.insert(SecretKey {
                    path: path.to_string(),
                    line: line_number,
                    rule: rule.name.to_string(),
                    confidence: rule.confidence,
                    sample: redacted_line(line, value, matched.start(), matched.end()),
                });
            }
        }

        let lower_line = line.to_lowercase();
        if has_credential_keyword(&lower_line) {
            add_assignment_findings(
                &mut findings,
                path,
                line_number,
                line,
                &ASSIGNMENT_SECRET_PATTERN,
                SecretConfidence::Medium,
            );
            if include_low_confidence {
                add_assignment_findings(
                    &mut findings,
                    path,
                    line_number,
                    line,
                    &LOW_CONFIDENCE_SECRET_PATTERN,
                    SecretConfidence::Low,
                );
            }
        }
    }
    findings
}

fn add_assignment_findings(
    findings: &mut HashSet<SecretKey>,
    path: &str,
    line_number: usize,
    line: &str,
    pattern: &Regex,
    confidence: SecretConfidence,
) {
    for captures in pattern.captures_iter(line) {
        let Some(whole) = captures.get(0) else {
            continue;
        };
        let Some(value_match) = captures.get(2) else {
            continue;
        };
        let value = value_match.as_str();
        if !is_plausible_assignment_secret(value, confidence) {
            continue;
        }
        findings.insert(SecretKey {
            path: path.to_string(),
            line: line_number,
            rule: if confidence == SecretConfidence::Low {
                "Credential-like name".to_string()
            } else {
                "Credential assignment".to_string()
            },
            confidence,
            sample: redacted_line(line, value, whole.start(), whole.end()),
        });
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

fn looks_like_test_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_lowercase();
    let file_name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_lowercase();
    normalized.contains("/test/")
        || normalized.contains("/tests/")
        || normalized.contains("/src/test/")
        || file_name.starts_with("test_")
        || file_name.ends_with("_test.py")
        || file_name.ends_with("test.java")
        || file_name.ends_with("tests.java")
        || file_name.ends_with(".test.js")
        || file_name.ends_with(".spec.js")
        || file_name.ends_with(".test.ts")
        || file_name.ends_with(".spec.ts")
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
        "- Findings shown: {} of {}{}",
        shown.len(),
        report.findings.len(),
        if truncated { " (truncated)" } else { "" }
    ));
    lines.blank();

    if shown.is_empty() {
        lines.line("No secret-like code found.");
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
        WorkspaceAnalyzer::build(std::sync::Arc::new(project), AnalyzerConfig::default())
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
    fn matcher_detects_credential_assignment_keyword_variants() {
        let text = r#"
        apiKey = "qQ9xV7pL2mN8rT4sZ6wY"
        api_key = "aB9xV7pL2mN8rT4sZ6wY"
        api-key = "zZ9xV7pL2mN8rT4sZ6wY"
        access_key = "mM9xV7pL2mN8rT4sZ6wY"
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
        let text = r#"
        password = "changeme"
        api_key = "test"
        token = "abcd123"
        "#;

        let normal_findings = scan_text("config.yml", text, false);
        let low_findings = scan_text("config.yml", text, true);

        assert!(normal_findings.is_empty(), "{normal_findings:?}");
        assert!(
            low_findings
                .iter()
                .any(|f| f.rule == "Credential-like name")
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
