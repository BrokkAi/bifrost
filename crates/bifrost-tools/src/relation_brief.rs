//! Request-local, target-anchored relations for a Git change.
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use brokk_bifrost_analysis::analyzer::i_analyzer::{
    AnalyzerQueryScope, IAnalyzer, QueryReadIncomplete,
};
use brokk_bifrost_core::analyzer::model::CodeUnit;
use brokk_bifrost_core::analyzer::query_token::{QueryScope, QueryToken};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::retention_budget::RetentionBudget;
use serde::{Deserialize, Serialize};

use crate::blast_radius::{normalized_path, test_file_context};
use crate::result_incomplete::ToolResultIncomplete;

use crate::diff_analysis::{
    CalleeChange, CommitSymbol, DiffAnalysisOptions, DiffCallAnalysis, DiffEndpointParams,
    DiffEndpoints, PreparedDiff, analyze_prepared_diff_with_endpoints,
    analyze_prepared_diff_with_target_image,
};
use crate::diff_scoring::changed_target_symbols;
use crate::searchtools::scan_usages::{
    ScanUsagesByLocationParams, ScanUsagesEntry, ScanUsagesExecutionContext,
    ScanUsagesIncompleteReason, ScanUsagesStatus, ScanUsagesTarget,
    scan_usages_by_location_with_context,
};
use crate::searchtools_render::{RenderOptions, RenderText};

// BrokkAi/mjolnir b1aed1fe: review-arms/brief/WRITER.md and brief_driver.py.
fn default_items() -> usize {
    25
}
fn default_chars() -> usize {
    7000
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelationBriefParams {
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub include_tests: bool,
    #[serde(default = "default_items")]
    pub max_items: usize,
    #[serde(default = "default_chars")]
    pub max_chars: usize,
}
impl RelationBriefParams {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=200).contains(&self.max_items) {
            return Err("max_items must be in 1..=200".into());
        }
        if !(1000..=100000).contains(&self.max_chars) {
            return Err("max_chars must be in 1000..=100000".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationBriefCause {
    Cancelled,
    TimeBudget,
    CandidateFiles,
    SourceBytes,
    SourceUnavailable,
    SemanticAnalysis,
    Callsites,
    ResponseBudget,
    ResolutionCandidates,
    UnmatchedPaths,
    TargetNotFound,
    TargetAmbiguous,
    AnalysisFailure,
    UnprovenReferences,
    SiteWithoutEnclosingDeclaration,
    CalleeUnresolved,
    CalleeAmbiguous,
    CallAnalysisIncomplete,
    CallerLocationUnavailable,
    DeletedSymbolNotScanned,
}
impl From<&QueryReadIncomplete> for RelationBriefCause {
    fn from(reason: &QueryReadIncomplete) -> Self {
        match reason.base_cause() {
            QueryReadIncomplete::Cancelled => Self::Cancelled,
            QueryReadIncomplete::StoreFailure(_) => Self::AnalysisFailure,
            QueryReadIncomplete::StructureUnavailable(_) => Self::SourceUnavailable,
            _ => Self::SemanticAnalysis,
        }
    }
}

impl From<ScanUsagesIncompleteReason> for RelationBriefCause {
    fn from(reason: ScanUsagesIncompleteReason) -> Self {
        match reason {
            ScanUsagesIncompleteReason::Cancelled => Self::Cancelled,
            ScanUsagesIncompleteReason::TimeBudget => Self::TimeBudget,
            ScanUsagesIncompleteReason::CandidateFiles => Self::CandidateFiles,
            ScanUsagesIncompleteReason::SourceBytes => Self::SourceBytes,
            ScanUsagesIncompleteReason::SourceUnavailable => Self::SourceUnavailable,
            ScanUsagesIncompleteReason::SemanticAnalysis => Self::SemanticAnalysis,
            ScanUsagesIncompleteReason::Callsites => Self::Callsites,
            ScanUsagesIncompleteReason::ResponseBudget => Self::ResponseBudget,
            ScanUsagesIncompleteReason::ResolutionCandidates => Self::ResolutionCandidates,
            ScanUsagesIncompleteReason::UnmatchedPaths => Self::UnmatchedPaths,
        }
    }
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct RelationCompleteness {
    pub complete: bool,
    // Cause vocabulary is deliberately open on the wire.
    #[schemars(with = "Vec<String>")]
    pub causes: Vec<RelationBriefCause>,
}
impl RelationCompleteness {
    fn complete() -> Self {
        Self {
            complete: true,
            causes: Vec::new(),
        }
    }
    fn add(&mut self, cause: RelationBriefCause) {
        self.complete = false;
        if !self.causes.contains(&cause) {
            self.causes.push(cause);
        }
    }
    fn join(&mut self, other: &Self) {
        for cause in &other.causes {
            self.add(*cause);
        }
    }
    fn suffix(&self) -> String {
        if self.complete {
            "[complete]".into()
        } else {
            format!("[incomplete: {}]", self.cause_text())
        }
    }
    fn cause_text(&self) -> String {
        self.causes
            .iter()
            .map(|cause| {
                let name = serde_json::to_value(cause).expect("cause serializes");
                format!("`{}`", name.as_str().expect("cause is a string"))
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct RelationAnchor {
    pub path: String,
    pub line: usize,
    pub in_change: bool,
}
impl RelationAnchor {
    fn at(prepared: &PreparedDiff, path: &str, line: usize) -> Self {
        Self {
            path: path.into(),
            line,
            in_change: prepared.target_line_changed(path, line),
        }
    }
    fn text(&self) -> String {
        format!("`{}:{}`", self.path, self.line)
    }
}

// The only constructor checks the target-side changed lines. Every item must
// consume one of these witnesses before it can become a serializable relation.
struct OutsideAnchor(RelationAnchor);
impl OutsideAnchor {
    fn new(prepared: &PreparedDiff, path: &str, line: usize) -> Option<Self> {
        let anchor = RelationAnchor::at(prepared, path, line);
        (!anchor.in_change).then_some(Self(anchor))
    }
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    AffectedCaller,
    PathInto,
    AddedCall,
    RemovedCall,
}
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct RelationBriefItem {
    relation: RelationKind,
    text: String,
    anchors: Vec<RelationAnchor>,
    subject: usize,
    completeness: RelationCompleteness,
}
impl RelationBriefItem {
    fn new(
        relation: RelationKind,
        text: String,
        outside: OutsideAnchor,
        mut anchors: Vec<RelationAnchor>,
        subject: usize,
        completeness: RelationCompleteness,
    ) -> Self {
        anchors.retain(|anchor| anchor.path != outside.0.path || anchor.line != outside.0.line);
        anchors.insert(0, outside.0);
        Self {
            relation,
            text: format!("{text} {}", completeness.suffix()),
            anchors,
            subject,
            completeness,
        }
    }
}
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct RelationBriefSubject {
    pub fqn: String,
    pub path: String,
    pub line: usize,
    pub change: String,
    pub first_hop: RelationCompleteness,
}
/// Deleted declaration positions belong to the base snapshot.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct RelationBriefDeletedSubject {
    pub fqn: String,
    pub path: String,
    pub line: usize,
    pub completeness: RelationCompleteness,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RelationSectionState {
    Computed,
    NotComputed,
}
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct RelationBriefSection {
    pub name: String,
    pub state: RelationSectionState,
    pub complete: bool,
    pub items: Vec<RelationBriefItem>,
    pub omitted_by_budget: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_computed_reason: Option<String>,
    pub notes: Vec<String>,
    pub notes_summarized: bool,
    #[serde(skip)]
    #[schemars(skip)]
    scan_completions: Vec<RelationCompleteness>,
    #[serde(skip)]
    #[schemars(skip)]
    summary_notes: Vec<String>,
    #[serde(skip)]
    #[schemars(skip)]
    call_analysis_summary: Option<String>,
    #[serde(skip)]
    #[schemars(skip)]
    deleted_note_summary: Option<String>,
}
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct RelationBriefBudget {
    pub max_items: usize,
    pub max_chars: usize,
    pub items: usize,
    pub chars: usize,
}
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct RelationBriefResult {
    pub incomplete: Vec<ToolResultIncomplete>,
    pub endpoints: DiffEndpoints,
    pub call_analysis: DiffCallAnalysis,
    pub budget: RelationBriefBudget,
    pub subjects: Vec<RelationBriefSubject>,
    pub deleted_subjects: Vec<RelationBriefDeletedSubject>,
    pub sections: Vec<RelationBriefSection>,
    pub brief: String,
}
impl RenderText for RelationBriefResult {
    fn render_text(&self, _options: RenderOptions) -> String {
        self.brief.clone()
    }
}

struct Caller {
    unit: CodeUnit,
    sites: Vec<RelationAnchor>,
}
struct Incoming {
    completeness: RelationCompleteness,
    callers: Vec<Caller>,
}

fn incoming(
    analyzer: &dyn IAnalyzer,
    prepared: &PreparedDiff,
    entry: ScanUsagesEntry,
    include_tests: bool,
) -> Incoming {
    let read_scope = AnalyzerQueryScope::new(analyzer);
    let mut completeness = RelationCompleteness::complete();
    if let Some(reason) = entry.completion.incomplete_reason() {
        completeness.add(reason.into());
    }
    match entry.status {
        ScanUsagesStatus::NotFound => completeness.add(RelationBriefCause::TargetNotFound),
        ScanUsagesStatus::Ambiguous => completeness.add(RelationBriefCause::TargetAmbiguous),
        ScanUsagesStatus::Failure => completeness.add(RelationBriefCause::AnalysisFailure),
        ScanUsagesStatus::TooManyCallsites => completeness.add(RelationBriefCause::Callsites),
        ScanUsagesStatus::UnverifiedAbsent => {
            completeness.add(RelationBriefCause::UnprovenReferences)
        }
        ScanUsagesStatus::Found
        | ScanUsagesStatus::VerifiedAbsent
        | ScanUsagesStatus::NoExternalUsages => {}
    }
    if !entry.unproven_files.is_empty() || entry.unproven_hits.is_some_and(|n| n > 0) {
        completeness.add(RelationBriefCause::UnprovenReferences);
    }
    // Ordered keys establish stable candidate order independent of scan scheduling.
    let mut callers = BTreeMap::new();
    for group in entry.files.iter().chain(&entry.same_owner_files) {
        let Some(file) = analyzer.project().file_by_rel_path(Path::new(&group.path)) else {
            completeness.add(RelationBriefCause::SiteWithoutEnclosingDeclaration);
            continue;
        };
        if !include_tests {
            match test_file_context(analyzer, &file) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(reason) => {
                    completeness.add((&reason).into());
                    analyzer.record_query_incomplete(reason);
                    continue;
                }
            }
        }
        for hit in &group.hits {
            let Some(unit) = analyzer.enclosing_code_unit_for_lines(
                &file,
                hit.line,
                hit.end_line.unwrap_or(hit.line),
            ) else {
                completeness.add(RelationBriefCause::SiteWithoutEnclosingDeclaration);
                continue;
            };
            if !include_tests {
                match analyzer.in_test_region(&unit) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(reason) => {
                        completeness.add((&reason).into());
                        analyzer.record_query_incomplete(reason);
                        continue;
                    }
                }
            }
            let Some(target) = scan_target(analyzer, &unit) else {
                completeness.add(RelationBriefCause::CallerLocationUnavailable);
                continue;
            };
            callers
                .entry((target.path, target.line, unit.fq_name()))
                .or_insert_with(|| Caller {
                    unit,
                    sites: Vec::new(),
                })
                .sites
                .push(RelationAnchor::at(prepared, &group.path, hit.line));
        }
    }
    let callers = callers
        .into_values()
        .map(|mut caller| {
            caller.sites.sort_by_key(|a| a.line);
            caller.sites.dedup_by_key(|a| a.line);
            caller
        })
        .collect();
    if let Err(reason) = read_scope.read_completion() {
        completeness.add((&reason).into());
    }
    Incoming {
        completeness,
        callers,
    }
}

fn scan_target(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<ScanUsagesTarget> {
    let range = analyzer
        .location_ranges(unit)
        .into_iter()
        .min_by_key(|r| (r.start_line, r.start_byte))?;
    Some(ScanUsagesTarget {
        path: normalized_path(unit.source().rel_path()),
        line: range.start_line.max(1),
        column: None,
        symbol: Some(unit.fq_name()),
    })
}
fn scan(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    targets: Vec<ScanUsagesTarget>,
    include_tests: bool,
    context: &ScanUsagesExecutionContext,
) -> Vec<ScanUsagesEntry> {
    if targets.is_empty() {
        return Vec::new();
    }
    scan_usages_by_location_with_context(
        analyzer,
        token,
        ScanUsagesByLocationParams {
            targets,
            include_tests,
            paths: None,
            include_same_owner: true,
        },
        context,
    )
    .results
}
fn site_text(unit: &CodeUnit, sites: &[RelationAnchor]) -> String {
    let first = &sites[0];
    let rest = sites[1..]
        .iter()
        .map(|s| format!(", {}", s.line))
        .collect::<String>();
    format!("`{}` ({}{rest})", unit.fq_name(), first.text())
}
fn subject_text(subject: &CommitSymbol) -> String {
    format!(
        "`{}` (`{}:{}`)",
        subject.fqn, subject.path, subject.start_line
    )
}
fn incomplete_note(subject: &CommitSymbol, completion: &RelationCompleteness) -> String {
    format!(
        "Incomplete scans: {}: {}.",
        subject_text(subject),
        completion.cause_text()
    )
}

pub fn relation_brief_at_root(
    root: &Path,
    params: RelationBriefParams,
    options: &DiffAnalysisOptions,
    cancellation: &CancellationToken,
    retention_budget: &RetentionBudget,
) -> Result<RelationBriefResult, String> {
    params.validate()?;
    let prepared = PreparedDiff::at_root(
        root,
        DiffEndpointParams {
            base: params.base.clone(),
            target: params.target.clone(),
        },
        options,
        cancellation,
        retention_budget,
    )?;
    let whole_target = prepared.whole_target_analysis()?;
    // The brief filters test subjects and callers itself; analyze_diff with
    // include_tests=false currently loses Rust call deltas (#13186).
    let analyzed = if prepared.target.is_immutable() {
        analyze_prepared_diff_with_target_image(&prepared, true, &whole_target)?
    } else {
        analyze_prepared_diff_with_endpoints(&prepared, true)?
    };
    let diff = analyzed.result;
    let analyzer = whole_target.analyzer();
    let scope = AnalyzerQueryScope::with_cancellation(analyzer, cancellation);
    let context = ScanUsagesExecutionContext::for_composite_query(cancellation.clone());
    let patch = &diff.patch_symbols;
    let mut subjects: Vec<_> = changed_target_symbols(patch).collect();
    for change in &patch.signature_changes {
        if let Some(existing) = subjects
            .iter_mut()
            .find(|(s, _)| s.path == change.after.path && s.start_line == change.after.start_line)
        {
            existing.1 = "signature_changed";
        } else {
            subjects.push((&change.after, "signature_changed"));
        }
    }
    subjects.retain(|(s, _)| params.include_tests || s.is_test != Some(true));
    subjects.sort_by_key(|(s, _)| {
        (
            prepared
                .file_changes
                .iter()
                .position(|f| f.path.as_ref() == Some(&s.path))
                .expect("a target subject belongs to a changed file"),
            s.start_line,
        )
    });
    let first = scan(
        analyzer,
        scope.token(),
        subjects
            .iter()
            .map(|(s, _)| ScanUsagesTarget {
                path: s.path.clone(),
                line: s.start_line,
                column: None,
                symbol: Some(s.fqn.clone()),
            })
            .collect(),
        params.include_tests,
        &context,
    )
    .into_iter()
    .map(|entry| incoming(analyzer, &prepared, entry, params.include_tests))
    .collect::<Vec<_>>();
    assert_eq!(
        first.len(),
        subjects.len(),
        "one scan entry per requested subject"
    );
    let mut second_targets = Vec::new();
    let mut seen = HashSet::new();
    for result in &first {
        for caller in &result.callers {
            if caller.unit.is_function() && seen.insert(caller.unit.declaration_id()) {
                second_targets.push((
                    caller.unit.declaration_id(),
                    scan_target(analyzer, &caller.unit).expect("caller already has location"),
                ));
            }
        }
    }
    let second_entries = scan(
        analyzer,
        scope.token(),
        second_targets.iter().map(|(_, t)| t.clone()).collect(),
        params.include_tests,
        &context,
    );
    assert_eq!(
        second_entries.len(),
        second_targets.len(),
        "one scan entry per requested caller"
    );
    let second: std::collections::HashMap<_, _> = second_targets
        .into_iter()
        .zip(second_entries)
        .map(|((id, _), entry)| {
            (
                id,
                incoming(analyzer, &prepared, entry, params.include_tests),
            )
        })
        .collect();
    let mut candidates = [
        vec![Vec::new(); subjects.len()],
        vec![Vec::new(); subjects.len()],
    ];
    let mut sections = vec![
        RelationBriefSection {
            name: "Affected callers".into(),
            state: RelationSectionState::Computed,
            complete: true,
            items: Vec::new(),
            omitted_by_budget: 0,
            not_computed_reason: None,
            notes: Vec::new(),
            notes_summarized: false,
            scan_completions: Vec::new(),
            summary_notes: Vec::new(),
            call_analysis_summary: None,
            deleted_note_summary: None,
        },
        RelationBriefSection {
            name: "Paths".into(),
            state: RelationSectionState::Computed,
            complete: true,
            items: Vec::new(),
            omitted_by_budget: 0,
            not_computed_reason: None,
            notes: Vec::new(),
            notes_summarized: false,
            scan_completions: Vec::new(),
            summary_notes: Vec::new(),
            call_analysis_summary: None,
            deleted_note_summary: None,
        },
        RelationBriefSection {
            name: "Value flow".into(),
            state: RelationSectionState::NotComputed,
            complete: false,
            items: Vec::new(),
            omitted_by_budget: 0,
            not_computed_reason: Some(
                "this version reads only call and reference relations".into(),
            ),
            notes: Vec::new(),
            notes_summarized: false,
            scan_completions: Vec::new(),
            summary_notes: Vec::new(),
            call_analysis_summary: None,
            deleted_note_summary: None,
        },
    ];
    // An incomplete inventory may omit subjects even when every returned scan completes.
    if !diff.incomplete.is_empty() {
        sections[0].complete = false;
        sections[1].complete = false;
    }
    let mut deleted_subjects: Vec<_> = patch
        .deleted
        .iter()
        .filter(|record| params.include_tests || record.before.is_test != Some(true))
        .map(|record| {
            let mut completeness = RelationCompleteness::complete();
            completeness.add(RelationBriefCause::DeletedSymbolNotScanned);
            RelationBriefDeletedSubject {
                fqn: record.before.fqn.clone(),
                path: record.before.path.clone(),
                line: record.before.start_line,
                completeness,
            }
        })
        .collect();
    deleted_subjects.sort_by(|left, right| {
        (&left.path, left.line, &left.fqn).cmp(&(&right.path, right.line, &right.fqn))
    });
    if !deleted_subjects.is_empty() {
        sections[0].complete = false;
        sections[1].complete = false;
        let count = deleted_subjects.len();
        let noun = if count == 1 { "symbol" } else { "symbols" };
        let details = deleted_subjects
            .iter()
            .map(|subject| {
                format!(
                    "`{}` (was `{}:{}` in the base)",
                    subject.fqn, subject.path, subject.line
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        sections[0]
            .notes
            .push(format!("Not scanned: {count} deleted {noun}: {details}."));
        sections[0].deleted_note_summary = Some(format!(
            "Not scanned: {count} deleted {noun}; causes: `deleted_symbol_not_scanned`."
        ));
    }
    // Call-inventory completeness belongs to the diff, rather than to every subject.
    let incomplete_endpoints: Vec<_> = [
        ("base", &diff.call_analysis.base),
        ("target", &diff.call_analysis.target),
    ]
    .into_iter()
    .filter_map(|(name, endpoint)| {
        endpoint
            .as_ref()
            .filter(|endpoint| !endpoint.complete)
            .map(|endpoint| (name, endpoint))
    })
    .collect();
    if !incomplete_endpoints.is_empty() {
        sections[1].complete = false;
        let names = incomplete_endpoints
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(", ");
        let mut seen = HashSet::new();
        let codes = incomplete_endpoints
            .iter()
            .flat_map(|(_, endpoint)| &endpoint.incomplete_reasons)
            .filter(|reason| seen.insert(reason.code.as_str()))
            .map(|reason| format!("`{}`", reason.code))
            .collect::<Vec<_>>()
            .join(", ");
        let reasons = if codes.is_empty() {
            String::new()
        } else {
            format!(": {codes}")
        };
        sections[1]
            .notes
            .push(format!("Call analysis incomplete at {names}{reasons}."));
        sections[1].call_analysis_summary = Some(format!(
            "Call analysis incomplete at {names}; see structured call_analysis for causes."
        ));
    }
    let mut output_subjects = Vec::new();
    for (index, ((subject, change), result)) in subjects.iter().zip(&first).enumerate() {
        let subject_anchor = RelationAnchor::at(&prepared, &subject.path, subject.start_line);
        let mut paths_completion = result.completeness.clone();
        for caller in &result.callers {
            let outside_sites: Vec<_> = caller
                .sites
                .iter()
                .filter(|site| !site.in_change)
                .cloned()
                .collect();
            if let Some(outside) = outside_sites
                .first()
                .and_then(|site| OutsideAnchor::new(&prepared, &site.path, site.line))
            {
                let mut anchors = outside_sites.clone();
                anchors.push(subject_anchor.clone());
                candidates[0][index].push(RelationBriefItem::new(
                    RelationKind::AffectedCaller,
                    format!(
                        "{} uses {}",
                        site_text(&caller.unit, &outside_sites),
                        subject_text(subject)
                    ),
                    outside,
                    anchors,
                    index,
                    result.completeness.clone(),
                ));
            }
            if let Some(next) = second.get(&caller.unit.declaration_id()) {
                paths_completion.join(&next.completeness);
                for grand in &next.callers {
                    let grand_target =
                        scan_target(analyzer, &grand.unit).expect("caller already has location");
                    if grand.unit.declaration_id() == caller.unit.declaration_id()
                        || (grand_target.path == subject.path
                            && grand_target.line == subject.start_line)
                    {
                        continue;
                    }
                    let mut completion = result.completeness.clone();
                    completion.join(&next.completeness);
                    let Some(outside) = grand
                        .sites
                        .iter()
                        .chain(&caller.sites)
                        .chain(std::iter::once(&subject_anchor))
                        .find_map(|site| OutsideAnchor::new(&prepared, &site.path, site.line))
                    else {
                        continue;
                    };
                    let mut anchors = grand.sites.clone();
                    anchors.extend(caller.sites.clone());
                    anchors.push(subject_anchor.clone());
                    candidates[1][index].push(RelationBriefItem::new(
                        RelationKind::PathInto,
                        format!(
                            "{} uses {}, which uses {}",
                            site_text(&grand.unit, &grand.sites),
                            site_text(&caller.unit, &caller.sites),
                            subject_text(subject)
                        ),
                        outside,
                        anchors,
                        index,
                        completion,
                    ));
                }
            }
        }
        let mut outgoing = Vec::new();
        for pair in &patch.edited {
            if pair.after.path == subject.path && pair.after.start_line == subject.start_line {
                outgoing.extend(pair.added_calls.iter().map(|c| (c, true)));
                outgoing.extend(pair.removed_calls.iter().map(|c| (c, false)));
            }
        }
        for pair in &patch.moved {
            if pair.after.path == subject.path && pair.after.start_line == subject.start_line {
                outgoing.extend(pair.added_calls.iter().map(|c| (c, true)));
                outgoing.extend(pair.removed_calls.iter().map(|c| (c, false)));
            }
        }
        for record in &patch.introduced {
            if record.after.path == subject.path && record.after.start_line == subject.start_line {
                outgoing.extend(record.calls.iter().map(|c| (c, true)));
            }
        }
        let mut seen_calls = HashSet::new();
        for (callee, added) in outgoing {
            if !seen_calls.insert((&callee.to, added)) {
                continue;
            }
            let Some(callee_anchor) = resolve_callee_anchor(
                analyzer,
                &prepared,
                callee,
                params.include_tests,
                &mut paths_completion,
            ) else {
                continue;
            };
            // A removed site is a base coordinate. Cite the surviving target declaration.
            let source_line = if added {
                callee
                    .sites
                    .iter()
                    .filter(|site| site.path == subject.path)
                    .map(|site| site.line)
                    .min()
                    .unwrap_or(subject.start_line)
            } else {
                subject.start_line
            };
            let source_anchor = RelationAnchor::at(&prepared, &subject.path, source_line);
            let Some(outside) =
                OutsideAnchor::new(&prepared, &callee_anchor.path, callee_anchor.line)
                    .or_else(|| OutsideAnchor::new(&prepared, &subject.path, source_line))
            else {
                continue;
            };
            let mut completion = RelationCompleteness::complete();
            if [&diff.call_analysis.base, &diff.call_analysis.target]
                .into_iter()
                .any(|endpoint| endpoint.as_ref().is_none_or(|endpoint| !endpoint.complete))
            {
                completion.add(RelationBriefCause::CallAnalysisIncomplete);
            }
            let (relation, text) = if added {
                (
                    RelationKind::AddedCall,
                    format!(
                        "`{}` ({}) now calls `{}` ({})",
                        subject.fqn,
                        source_anchor.text(),
                        callee.to,
                        callee_anchor.text()
                    ),
                )
            } else {
                (
                    RelationKind::RemovedCall,
                    format!(
                        "the diff removes the call from `{}` ({}) to `{}` ({})",
                        subject.fqn,
                        source_anchor.text(),
                        callee.to,
                        callee_anchor.text()
                    ),
                )
            };
            candidates[1][index].push(RelationBriefItem::new(
                relation,
                text,
                outside,
                vec![source_anchor, callee_anchor],
                index,
                completion,
            ));
        }
        for (section, completion) in sections[..2]
            .iter_mut()
            .zip([&result.completeness, &paths_completion])
        {
            if !completion.complete {
                section.complete = false;
                section.notes.push(incomplete_note(subject, completion));
                section.scan_completions.push(completion.clone());
            }
        }
        output_subjects.push(RelationBriefSubject {
            fqn: subject.fqn.clone(),
            path: subject.path.clone(),
            line: subject.start_line,
            change: (*change).into(),
            first_hop: result.completeness.clone(),
        });
    }
    Ok(select_and_render(
        RelationBriefResult {
            incomplete: diff.incomplete,
            endpoints: diff.endpoints,
            call_analysis: diff.call_analysis,
            budget: RelationBriefBudget {
                max_items: params.max_items,
                max_chars: params.max_chars,
                items: 0,
                chars: 0,
            },
            subjects: output_subjects,
            deleted_subjects,
            sections,
            brief: String::new(),
        },
        candidates,
        &params,
    ))
}

fn resolve_callee_anchor(
    analyzer: &dyn IAnalyzer,
    prepared: &PreparedDiff,
    callee: &CalleeChange,
    include_tests: bool,
    paths_completion: &mut RelationCompleteness,
) -> Option<RelationAnchor> {
    let scope = AnalyzerQueryScope::new(analyzer);
    let definitions: Vec<_> = analyzer.definitions(&callee.to).collect();
    if let Err(reason) = scope.read_completion() {
        paths_completion.add((&reason).into());
        return None;
    }
    let [unit] = definitions.as_slice() else {
        paths_completion.add(if definitions.is_empty() {
            RelationBriefCause::CalleeUnresolved
        } else {
            RelationBriefCause::CalleeAmbiguous
        });
        return None;
    };
    if !include_tests {
        let in_test_context =
            match test_file_context(analyzer, unit.source()).and_then(|file_is_test| {
                if file_is_test {
                    Ok(true)
                } else {
                    analyzer.in_test_region(unit)
                }
            }) {
                Ok(value) => value,
                Err(reason) => {
                    paths_completion.add((&reason).into());
                    analyzer.record_query_incomplete(reason);
                    return None;
                }
            };
        if let Err(reason) = scope.read_completion() {
            paths_completion.add((&reason).into());
            return None;
        }
        if in_test_context {
            return None;
        }
    }
    let Some(target) = scan_target(analyzer, unit) else {
        paths_completion.add(RelationBriefCause::CallerLocationUnavailable);
        return None;
    };
    if let Err(reason) = scope.read_completion() {
        paths_completion.add((&reason).into());
        return None;
    }
    Some(RelationAnchor::at(prepared, &target.path, target.line))
}

fn select_and_render(
    mut result: RelationBriefResult,
    candidates: [Vec<Vec<RelationBriefItem>>; 2],
    params: &RelationBriefParams,
) -> RelationBriefResult {
    let incomplete = &result.incomplete;
    let sections = &mut result.sections;
    // Each section queue round-robins over subjects; selection alternates sections.
    let queues: Vec<_> = candidates
        .iter()
        .map(|by_subject| {
            let rounds = by_subject.iter().map(Vec::len).max().unwrap_or(0);
            (0..rounds)
                .flat_map(|round| {
                    by_subject
                        .iter()
                        .enumerate()
                        .filter_map(move |(subject, items)| {
                            (round < items.len()).then_some((subject, round))
                        })
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let mut selected = Vec::new();
    let rounds = queues.iter().map(Vec::len).max().unwrap_or(0);
    'rounds: for round in 0..rounds {
        for (section, queue) in queues.iter().enumerate() {
            if let Some(&(subject, candidate)) = queue.get(round) {
                selected.push((section, subject, candidate));
                if selected.len() == params.max_items {
                    break 'rounds;
                }
            }
        }
    }
    let mut summaries_prepared = false;
    let brief = loop {
        for (index, section) in sections[..2].iter_mut().enumerate() {
            section.items.clear();
            section.omitted_by_budget = candidates[index].iter().map(Vec::len).sum();
        }
        let mut ordered = selected.clone();
        ordered.sort_unstable();
        for (section, subject, candidate) in ordered {
            sections[section]
                .items
                .push(candidates[section][subject][candidate].clone());
            sections[section].omitted_by_budget -= 1;
        }
        let rendered = render(incomplete, sections);
        if rendered.chars().count() <= params.max_chars {
            break rendered;
        }
        if !summaries_prepared {
            for section in sections.iter_mut() {
                if !section.scan_completions.is_empty() {
                    let mut completion = RelationCompleteness::complete();
                    for scan in &section.scan_completions {
                        completion.join(scan);
                    }
                    // The diff-wide call note precedes all per-subject scan notes.
                    let prefix = section.notes.len() - section.scan_completions.len();
                    section.summary_notes = section.notes[..prefix].to_vec();
                    let count = section.scan_completions.len();
                    let noun = if count == 1 { "symbol" } else { "symbols" };
                    section.summary_notes.push(format!(
                        "Incomplete scans for {count} changed {noun}; causes: {}.",
                        completion.cause_text()
                    ));
                    section.notes_summarized = true;
                }
                if let Some(summary) = &section.deleted_note_summary {
                    if !section.notes_summarized {
                        section.summary_notes = section.notes.clone();
                    }
                    section.summary_notes[0] = summary.clone();
                    section.notes_summarized = true;
                }
            }
            // Compact the one diff-wide call note only when the zero-item
            // skeleton still exceeds the limit. Keep its full codes in JSON.
            let mut skeleton = sections.clone();
            for (section, by_subject) in skeleton[..2].iter_mut().zip(&candidates) {
                section.items.clear();
                section.omitted_by_budget = by_subject.iter().map(Vec::len).sum();
            }
            if render(incomplete, &skeleton).chars().count() > params.max_chars {
                for section in sections.iter_mut() {
                    if let Some(summary) = &section.call_analysis_summary {
                        if !section.notes_summarized {
                            section.summary_notes = section.notes.clone();
                        }
                        section.summary_notes[0] = summary.clone();
                        section.notes_summarized = true;
                    }
                }
            }
            summaries_prepared = true;
            continue;
        }
        if selected.is_empty() {
            break rendered;
        }
        selected.pop();
    };
    result.budget.items = selected.len();
    result.budget.chars = brief.chars().count();
    result.brief = brief;
    result
}
fn render(incomplete: &[ToolResultIncomplete], sections: &[RelationBriefSection]) -> String {
    let mut text = String::new();
    if !incomplete.is_empty() {
        let mut seen = Vec::new();
        let reasons = incomplete
            .iter()
            .filter(|entry| {
                if seen.contains(&entry.reason) {
                    false
                } else {
                    seen.push(entry.reason);
                    true
                }
            })
            .map(|entry| {
                let name = serde_json::to_value(entry.reason).expect("typed reason serializes");
                format!("`{}`", name.as_str().expect("typed reason is a string"))
            })
            .collect::<Vec<_>>()
            .join(", ");
        text.push_str(&format!("Diff inventory incomplete: {reasons}.\n"));
    }
    for section in sections {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&format!("## {}\n", section.name));
        if let Some(reason) = &section.not_computed_reason {
            text.push_str(&format!("Not computed: {reason}.\n"));
        } else {
            if section.items.is_empty() && section.complete && section.omitted_by_budget == 0 {
                text.push_str("- none\n");
            }
            for item in &section.items {
                text.push_str(&format!("- {}\n", item.text));
            }
            let notes = if section.notes_summarized {
                &section.summary_notes
            } else {
                &section.notes
            };
            for note in notes {
                text.push_str(note);
                text.push('\n');
            }
            if section.omitted_by_budget > 0 {
                if section.omitted_by_budget == 1 {
                    text.push_str("1 more relation in this section was left out by the item and size budget.\n");
                } else {
                    text.push_str(&format!("{} more relations in this section were left out by the item and size budget.\n", section.omitted_by_budget));
                }
            }
        }
    }
    text
}
