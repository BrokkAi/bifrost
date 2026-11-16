//! Inline comment directives that accept policy findings at their line.
//!
//! A directive is a source comment such as
//! `// bifrost: ignore[some.policy, other.policy] -- reason`. The comment is
//! found structurally, from the analyzer's normalized `comment` facts; only the
//! text of a comment node the parser selected is classified here. A directive
//! alone on its line covers the next line that holds code; a directive after
//! code covers its own line. A blanket directive (no policy list) must carry a
//! reason, or it accepts nothing.
//!
//! Directives are scanned once before evaluation. The evaluator hint and the
//! report acceptance join borrow the same scan; only the report confirms claims.

use brokk_bifrost_core::retention_budget::{
    AllocationCharge, BudgetRegion, ENTRY_OVERHEAD_BYTES, RetentionBudget, SelfCharged,
    SharedAllocation,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::mem::size_of;
use std::sync::{Arc, Mutex};

use serde::Serialize;

use brokk_bifrost_analysis::analyzer::structural::{FileFacts, Span};
use brokk_bifrost_analysis::analyzer::{ProjectFile, WorkspaceAnalyzer};
use brokk_bifrost_rql::structural::NormalizedKind;

use super::classification::{TextValidationError, validate_single_line_text};
use super::definition::PolicyId;
use super::finding::PolicyRun;
use super::retained::{RetainedSize, retained_extra};

/// The word a directive starts with when no host chooses another.
pub const DEFAULT_INLINE_SUPPRESSION_PREFIX: &str = "bifrost";
pub const MAX_INLINE_SUPPRESSION_PREFIX_BYTES: usize = 32;
pub const MAX_INLINE_SUPPRESSION_REASON_BYTES: usize = 4_096;
/// Directives retained in one report's audit. Later ones still apply; the
/// audit counts them in `omitted_directives`.
pub const MAX_INLINE_SUPPRESSION_REVIEWS: usize = 4_096;

const DIRECTIVE_WORD: &str = "ignore";

/// The word before the colon of a directive, for example `bifrost` in
/// `// bifrost: ignore`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct InlineSuppressionPrefix(Cow<'static, str>);

impl InlineSuppressionPrefix {
    pub fn new(word: &str) -> Result<Self, InlineSuppressionPrefixError> {
        if word.is_empty() || word.len() > MAX_INLINE_SUPPRESSION_PREFIX_BYTES {
            return Err(InlineSuppressionPrefixError::Length {
                max_bytes: MAX_INLINE_SUPPRESSION_PREFIX_BYTES,
            });
        }
        if !word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(InlineSuppressionPrefixError::Character);
        }
        Ok(Self(Cow::Owned(word.to_owned())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl InlineSuppressionPrefix {
    pub const DEFAULT: Self = Self(Cow::Borrowed(DEFAULT_INLINE_SUPPRESSION_PREFIX));
}

impl Default for InlineSuppressionPrefix {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for InlineSuppressionPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InlineSuppressionPrefixError {
    Length { max_bytes: usize },
    Character,
}

impl fmt::Display for InlineSuppressionPrefixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { max_bytes } => write!(
                formatter,
                "an inline suppression prefix must be 1 to {max_bytes} bytes"
            ),
            Self::Character => formatter.write_str(
                "an inline suppression prefix may contain only ASCII letters, digits, `-` and `_`",
            ),
        }
    }
}

impl std::error::Error for InlineSuppressionPrefixError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyInlineSuppressionOptions {
    prefix: InlineSuppressionPrefix,
}

impl PolicyInlineSuppressionOptions {
    pub const DEFAULT: Self = Self::new(InlineSuppressionPrefix::DEFAULT);

    pub const fn new(prefix: InlineSuppressionPrefix) -> Self {
        Self { prefix }
    }

    pub const fn prefix(&self) -> &InlineSuppressionPrefix {
        &self.prefix
    }
}

/// One parsed directive. An empty policy list is a blanket directive.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Directive {
    policies: Vec<PolicyId>,
    reason: Option<Box<str>>,
}

/// Classify the text of one comment node. `None` means the comment is not a
/// directive; `Some(Err(detail))` means it starts as an `ignore` directive but
/// the rest does not parse.
fn parse_directive(prefix: &str, comment: &str) -> Option<Result<Directive, String>> {
    // Strip the comment delimiters of every supported language: `//`, `///`,
    // `//!`, `/*`, `/**`, a leading `*` on a block-comment line, and `#`.
    let body = comment
        .trim_start_matches(|character: char| {
            character.is_whitespace() || matches!(character, '/' | '*' | '#' | '!')
        })
        .trim_end();
    let body = body.strip_suffix("*/").unwrap_or(body).trim_end();
    let rest = body.strip_prefix(prefix)?.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix(DIRECTIVE_WORD)?;
    // `bifrost: ignored because ...` is prose, not a directive.
    if rest
        .chars()
        .next()
        .is_some_and(|next| !next.is_whitespace() && next != '[')
    {
        return None;
    }
    Some(parse_directive_tail(rest.trim_start()))
}

fn parse_directive_tail(rest: &str) -> Result<Directive, String> {
    let (policies, rest) = match rest.strip_prefix('[') {
        Some(list) => {
            let (list, rest) = list
                .split_once(']')
                .ok_or_else(|| "the policy list has no closing `]`".to_string())?;
            let mut policies = Vec::new();
            for item in list.split(',') {
                let item = item.trim();
                let policy = PolicyId::new(item)
                    .map_err(|error| format!("`{item}` is not a policy id: {error}"))?;
                policies.push(policy);
            }
            (policies, rest.trim_start())
        }
        None => (Vec::new(), rest),
    };
    let reason = if rest.is_empty() {
        None
    } else {
        let reason = rest
            .strip_prefix("--")
            .ok_or_else(|| format!("unexpected text `{rest}`; write a reason after `--`"))?
            .trim();
        if reason.is_empty() {
            None
        } else {
            validate_single_line_text(reason, MAX_INLINE_SUPPRESSION_REASON_BYTES).map_err(
                |error| match error {
                    TextValidationError::TooLong { max_bytes } => {
                        format!("the reason is longer than {max_bytes} bytes")
                    }
                    other => format!("the reason is not one line of text: {other:?}"),
                },
            )?;
            Some(reason.into())
        }
    };
    Ok(Directive { policies, reason })
}

/// A directive found in one file, with the line it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LocatedDirective {
    line: u64,
    covered_line: Option<u64>,
    directive: Result<Directive, String>,
}

/// Every directive in `facts`, in source order. Comment facts come from the
/// language adapter's grammar mapping, so this reads no source text except the
/// selected comments and the layout around them.
fn located_directives(facts: &FileFacts, prefix: &str) -> Vec<LocatedDirective> {
    let mut comments = facts
        .nodes()
        .iter()
        .filter(|node| node.kind == NormalizedKind::Comment)
        .map(|node| node.span())
        .collect::<Vec<_>>();
    comments.sort_unstable_by_key(|span| (span.start_byte, span.end_byte));
    comments.dedup();
    let source = facts.source();
    comments
        .iter()
        .filter_map(|span| {
            let directive = parse_directive(prefix, span.text(source))?;
            let line = line_number(facts, span.start_byte);
            Some(LocatedDirective {
                line,
                covered_line: covered_line(facts, &comments, *span),
                directive,
            })
        })
        .collect()
}

fn line_number(facts: &FileFacts, byte: usize) -> u64 {
    u64::try_from(facts.line_of_byte(byte)).expect("line numbers fit in u64")
}

/// The line a directive in `comment` covers: its own line when code shares
/// it, otherwise the next line holding code. `None` when no code follows.
fn covered_line(facts: &FileFacts, comments: &[Span], comment: Span) -> Option<u64> {
    let source = facts.source();
    let line_start = source[..comment.start_byte]
        .rfind('\n')
        .map_or(0, |index| index + 1);
    if has_code(source, comments, line_start, comment.start_byte) {
        return Some(line_number(facts, comment.start_byte));
    }
    let end_line_end = source[comment.end_byte..]
        .find('\n')
        .map_or(source.len(), |index| comment.end_byte + index);
    if has_code(source, comments, comment.end_byte, end_line_end) {
        return Some(line_number(facts, comment.end_byte));
    }
    let mut start = end_line_end + 1;
    while start < source.len() {
        let end = source[start..]
            .find('\n')
            .map_or(source.len(), |index| start + index);
        if has_code(source, comments, start, end) {
            return Some(line_number(facts, start));
        }
        start = end + 1;
    }
    None
}

/// Whether `source[start..end]` has a non-whitespace character outside every
/// comment span. `comments` is sorted by start byte.
fn has_code(source: &str, comments: &[Span], start: usize, end: usize) -> bool {
    let mut cursor = start;
    let first = comments.partition_point(|span| span.end_byte <= start);
    for span in &comments[first..] {
        if span.start_byte >= end {
            break;
        }
        if span.start_byte > cursor && !source[cursor..span.start_byte].trim().is_empty() {
            return true;
        }
        cursor = cursor.max(span.end_byte);
    }
    cursor < end && !source[cursor..end].trim().is_empty()
}

/// The directive that accepted a finding, attached to the finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyFindingInlineSuppression {
    /// One-based line of the directive's comment.
    line: u64,
    /// The policies the directive names; empty for a blanket directive.
    policies: Vec<PolicyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<Box<str>>,
}

impl PolicyFindingInlineSuppression {
    pub const fn line(&self) -> u64 {
        self.line
    }

    pub fn policies(&self) -> &[PolicyId] {
        &self.policies
    }

    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

impl RetainedSize for PolicyFindingInlineSuppression {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.policies))
            .saturating_add(retained_extra(&self.reason))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyInlineSuppressionState {
    /// The directive accepted at least one finding.
    Applied,
    /// The directive is valid but no finding of this run starts on the line
    /// it covers.
    Unused,
    /// A blanket directive without a reason accepts nothing.
    MissingReason,
    /// The directive starts as `<prefix>: ignore` but does not parse.
    Malformed,
}

/// Audit entry for one directive found in a file with findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyInlineSuppressionEntry {
    path: Box<str>,
    line: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    covered_line: Option<u64>,
    policies: Vec<PolicyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<Box<str>>,
    state: PolicyInlineSuppressionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<Box<str>>,
    matched_findings: u64,
}

impl PolicyInlineSuppressionEntry {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub const fn line(&self) -> u64 {
        self.line
    }

    pub const fn covered_line(&self) -> Option<u64> {
        self.covered_line
    }

    pub fn policies(&self) -> &[PolicyId] {
        &self.policies
    }

    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    pub const fn state(&self) -> PolicyInlineSuppressionState {
        self.state
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    pub const fn matched_findings(&self) -> u64 {
        self.matched_findings
    }
}

impl RetainedSize for PolicyInlineSuppressionEntry {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.path))
            .saturating_add(retained_extra(&self.policies))
            .saturating_add(retained_extra(&self.reason))
            .saturating_add(retained_extra(&self.detail))
    }
}

/// The report's audit of every directive read in this run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyInlineSuppressionReview {
    prefix: InlineSuppressionPrefix,
    entries: Vec<PolicyInlineSuppressionEntry>,
    #[serde(skip_serializing_if = "crate::is_zero")]
    omitted_entries: u64,
}

impl PolicyInlineSuppressionReview {
    pub const fn prefix(&self) -> &InlineSuppressionPrefix {
        &self.prefix
    }

    pub fn entries(&self) -> &[PolicyInlineSuppressionEntry] {
        &self.entries
    }

    pub const fn omitted_entries(&self) -> u64 {
        self.omitted_entries
    }
}

impl RetainedSize for PolicyInlineSuppressionReview {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(match &self.prefix.0 {
                Cow::Borrowed(_) => 0,
                Cow::Owned(word) => word.capacity(),
            })
            .saturating_add(retained_extra(&self.entries))
    }
}

/// One request's lazily scanned files. Retention and report joins share the
/// same parse, including empty results. The owner charge pins each answer for
/// this request even if its fresh region refuses admission or evicts it.
pub(crate) struct InlineDirectiveScan<'a> {
    workspace: Option<&'a WorkspaceAnalyzer>,
    options: &'a PolicyInlineSuppressionOptions,
    budget: &'a RetentionBudget,
    files: Mutex<HashMap<String, Arc<ScannedDirectives>>>,
    region: BudgetRegion<String, SharedAllocation<ScannedDirectives>>,
}

struct ScannedDirectives {
    located: Vec<LocatedDirective>,
    charge: AllocationCharge,
}
impl SelfCharged for ScannedDirectives {
    fn allocation_charge(&self) -> &AllocationCharge {
        &self.charge
    }
}
impl RetainedSize for Directive {
    fn retained_size(&self) -> usize {
        size_of::<Self>() + retained_extra(&self.policies) + retained_extra(&self.reason)
    }
}
impl RetainedSize for LocatedDirective {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            + match &self.directive {
                Ok(directive) => directive
                    .retained_size()
                    .saturating_sub(size_of::<Directive>()),
                Err(detail) => detail.capacity(),
            }
    }
}

/// All locations consulted by inline matching and report scanning. There are
/// no enclosing-item or file-level directives: coverage is line-based.
fn inline_locations(
    finding: &crate::PolicyFinding,
) -> impl Iterator<Item = &crate::PolicySourceLocation> {
    std::iter::once(finding.primary()).chain(finding.evaluation_location())
}

impl<'a> InlineDirectiveScan<'a> {
    pub(crate) fn new(
        options: &'a PolicyInlineSuppressionOptions,
        workspace: Option<&'a WorkspaceAnalyzer>,
        budget: &'a RetentionBudget,
    ) -> Self {
        let budget = workspace.map_or(budget, WorkspaceAnalyzer::retention_budget);
        Self {
            workspace,
            options,
            budget,
            files: Mutex::new(HashMap::new()),
            region: budget.region("policy.inline-directives.request", None),
        }
    }

    fn file(&self, path: &str) -> Arc<ScannedDirectives> {
        let mut files = self.files.lock().expect("inline directive memo poisoned");
        if let Some(scanned) = files.get(path) {
            return Arc::clone(scanned);
        }
        let located = self.workspace.map_or_else(Vec::new, |workspace| {
            let analyzer = workspace.analyzer();
            let file = ProjectFile::new(analyzer.project().root(), std::path::Path::new(path));
            // Exactly the analyzed-source membership used by analyzed_files(),
            // with a point lookup rather than enumerating the workspace. No
            // hint or report scan can read an external/non-analyzed location.
            if !analyzer.is_analyzed(&file) {
                return Vec::new();
            }
            analyzer
                .structural_fact_providers()
                .iter()
                .find_map(|provider| provider.structural_facts(&file))
                .map_or_else(Vec::new, |facts| {
                    located_directives(&facts, self.options.prefix().as_str())
                })
        });
        // The conservative per-entry allowance also covers the request's map
        // key, Arc and hash-table slack. Required charging keeps once-per-file
        // semantics independent of parallel fill order and region pressure.
        let allocation = brokk_bifrost_core::allocation_size::allocation_size;
        let owned = allocation(located.capacity() * size_of::<LocatedDirective>())
            + located
                .iter()
                .map(|located| match &located.directive {
                    Ok(directive) => {
                        allocation(directive.policies.capacity() * size_of::<PolicyId>())
                            + directive
                                .policies
                                .iter()
                                .map(|id| allocation(id.as_str().len()))
                                .sum::<usize>()
                            + directive
                                .reason
                                .as_ref()
                                .map_or(0, |reason| allocation(reason.len()))
                    }
                    Err(detail) => allocation(detail.capacity()),
                })
                .sum::<usize>();
        // This required request-owned payload belongs to the P owner's scan;
        // report RetainedSize formulas remain raw for their separate limits.
        let bytes =
            size_of::<ScannedDirectives>() + owned + allocation(path.len()) + ENTRY_OVERHEAD_BYTES;
        let scanned = Arc::new(ScannedDirectives {
            located,
            charge: AllocationCharge::acquire_required(self.budget, bytes),
        });
        let admitted = self
            .region
            .insert_shared(path.to_owned(), SharedAllocation::new(Arc::clone(&scanned)));
        drop(admitted);
        files.insert(path.to_owned(), Arc::clone(&scanned));
        scanned
    }

    pub(crate) fn candidate_matches(&self, finding: &crate::PolicyFinding) -> bool {
        inline_locations(finding)
            .filter(|location| location.region().is_some())
            .any(|location| {
                let scanned = self.file(location.path());
                scanned
                    .located
                    .iter()
                    .any(|directive| inline_candidate_matches(location.path(), directive, finding))
            })
    }
}
impl Drop for InlineDirectiveScan<'_> {
    fn drop(&mut self) {
        self.region.invalidate_all();
    }
}

fn inline_candidate_matches(
    path: &str,
    located: &LocatedDirective,
    finding: &crate::PolicyFinding,
) -> bool {
    let Ok(directive) = &located.directive else {
        return false;
    };
    located
        .covered_line
        .is_some_and(|line| finding_is_covered(finding, path, line))
        && (directive.policies.is_empty() || directive.policies.contains(finding.policy_id()))
}

/// Attach cached directives to unclaimed findings and return their audit.
/// Only files holding those findings contribute audit entries.
pub(crate) fn apply_inline_suppressions(
    options: &PolicyInlineSuppressionOptions,
    scan: &InlineDirectiveScan<'_>,
    runs: &mut HashMap<PolicyId, PolicyRun>,
) -> Option<PolicyInlineSuppressionReview> {
    let paths = runs
        .values()
        .flat_map(PolicyRun::findings)
        .filter(|finding| !finding.is_explicitly_accepted())
        .flat_map(inline_locations)
        .filter(|location| location.region().is_some())
        .map(|location| location.path().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    let mut entries = Vec::new();
    for path in paths {
        let scanned = scan.file(&path);
        for directive in &scanned.located {
            entries.push(match_directive(&path, directive.clone(), runs));
        }
    }
    let omitted_entries = entries.len().saturating_sub(MAX_INLINE_SUPPRESSION_REVIEWS);
    entries.truncate(MAX_INLINE_SUPPRESSION_REVIEWS);
    entries.shrink_to_fit();
    if entries.is_empty() {
        return None;
    }
    Some(PolicyInlineSuppressionReview {
        prefix: options.prefix().clone(),
        entries,
        omitted_entries: u64::try_from(omitted_entries).unwrap_or(u64::MAX),
    })
}

fn match_directive(
    path: &str,
    located: LocatedDirective,
    runs: &mut HashMap<PolicyId, PolicyRun>,
) -> PolicyInlineSuppressionEntry {
    let candidate = located.clone();
    let LocatedDirective {
        line,
        covered_line,
        directive,
    } = located;
    let directive = match directive {
        Ok(directive) => directive,
        Err(detail) => {
            return PolicyInlineSuppressionEntry {
                path: path.into(),
                line,
                covered_line,
                policies: Vec::new(),
                reason: None,
                state: PolicyInlineSuppressionState::Malformed,
                detail: Some(detail.into()),
                matched_findings: 0,
            };
        }
    };
    let mut entry = PolicyInlineSuppressionEntry {
        path: path.into(),
        line,
        covered_line,
        policies: directive.policies.clone(),
        reason: directive.reason.clone(),
        state: PolicyInlineSuppressionState::Unused,
        detail: None,
        matched_findings: 0,
    };
    if directive.policies.is_empty() && directive.reason.is_none() {
        entry.state = PolicyInlineSuppressionState::MissingReason;
        return entry;
    }
    let Some(_) = covered_line else {
        return entry;
    };
    let attachment = PolicyFindingInlineSuppression {
        line,
        policies: directive.policies,
        reason: directive.reason,
    };
    for run in runs.values_mut() {
        for finding in run.findings_mut() {
            if finding.is_explicitly_accepted()
                || !inline_candidate_matches(path, &candidate, finding)
            {
                continue;
            }
            finding.attach_inline_suppression(attachment.clone());
            entry.matched_findings += 1;
        }
    }
    if entry.matched_findings > 0 {
        entry.state = PolicyInlineSuppressionState::Applied;
    }
    entry
}

/// A directive may cover either the evaluation point or rendered operand evidence.
/// Old reports without evaluation evidence retain primary-only coverage.
fn finding_is_covered(finding: &crate::PolicyFinding, path: &str, line: u64) -> bool {
    inline_locations(finding).any(|location| {
        location.path() == path
            && location
                .region()
                .is_some_and(|region| region.start_line() == line)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directive_memo_scans_only_requested_analyzed_files_once_and_charges_the_owner() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("app.ts"),
            "// bifrost: ignore[test.audit] -- reviewed\nexport function target() {}\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("untouched.ts"),
            "export function untouched() {}\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("outside.json"),
            "// bifrost: ignore[test.audit] -- never analyzed\n",
        )
        .unwrap();
        let project =
            brokk_bifrost_analysis::FilesystemProject::new(root.path().to_path_buf()).unwrap();
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(Arc::new(project), Default::default())
                .unwrap();
        // No capacity remains for a cache admission. The once-per-file result
        // must remain shared and charged for the lifetime of this request.
        let budget = RetentionBudget::for_test_capacity(0);
        let options = PolicyInlineSuppressionOptions::DEFAULT;
        let memo = InlineDirectiveScan {
            workspace: Some(&workspace),
            options: &options,
            budget: &budget,
            files: Mutex::new(HashMap::new()),
            region: budget.region("policy.inline-directives.test", None),
        };
        assert!(memo.files.lock().unwrap().is_empty());
        let first = memo.file("app.ts");
        assert_eq!(first.located.len(), 1);
        let second = memo.file("app.ts");
        assert!(Arc::ptr_eq(&first, &second));
        let outside = memo.file("outside.json");
        assert!(outside.located.is_empty());
        assert_eq!(
            memo.files
                .lock()
                .unwrap()
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            ["app.ts".to_owned(), "outside.json".to_owned()].into()
        );
        assert!(budget.occupied_bytes() > 0);
        drop(first);
        drop(second);
        drop(outside);
        drop(memo);
        budget.run_pending_tasks();
        assert_eq!(budget.occupied_bytes(), 0);
    }

    fn parse(comment: &str) -> Option<Result<Directive, String>> {
        parse_directive("bifrost", comment)
    }

    fn ids(directive: &Directive) -> Vec<&str> {
        directive.policies.iter().map(PolicyId::as_str).collect()
    }

    #[test]
    fn directive_grammar_across_comment_delimiters() {
        let listed = parse("// bifrost: ignore[a.b, c-d.e] -- checked above")
            .unwrap()
            .unwrap();
        assert_eq!(ids(&listed), ["a.b", "c-d.e"]);
        assert_eq!(listed.reason.as_deref(), Some("checked above"));

        for comment in [
            "# bifrost: ignore[a.b]",
            "/// bifrost: ignore[a.b]",
            "//! bifrost:ignore[a.b]",
            "/* bifrost: ignore [a.b] */",
            "/**\n * bifrost: ignore[a.b]\n */",
        ] {
            let directive = parse(comment).unwrap().unwrap();
            assert_eq!(ids(&directive), ["a.b"], "{comment}");
            assert_eq!(directive.reason, None, "{comment}");
        }

        let blanket = parse("# bifrost: ignore -- generated").unwrap().unwrap();
        assert!(blanket.policies.is_empty());
        assert_eq!(blanket.reason.as_deref(), Some("generated"));
        let bare = parse("// bifrost: ignore").unwrap().unwrap();
        assert!(bare.policies.is_empty() && bare.reason.is_none());

        // Prose that merely starts with the prefix is not a directive.
        assert_eq!(parse("// bifrost: this module owns the cache"), None);
        assert_eq!(parse("// bifrost: ignored on purpose"), None);
        assert_eq!(parse("// see bifrost: ignore[a.b]"), None);
        assert_eq!(parse("// slopcop: ignore[a.b]"), None);
        assert!(parse_directive("slopcop", "// slopcop: ignore[a.b]").is_some());

        for malformed in [
            "// bifrost: ignore[a.b",
            "// bifrost: ignore[]",
            "// bifrost: ignore[a.b,]",
            "// bifrost: ignore[a.b] because",
            "/* bifrost: ignore -- two\n lines */",
        ] {
            assert!(parse(malformed).unwrap().is_err(), "{malformed}");
        }
    }
}
