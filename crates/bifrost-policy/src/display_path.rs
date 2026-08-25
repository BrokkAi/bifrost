//! Bounded, non-canonical display paths for concise taint findings.

use std::cmp::Ordering;
use std::collections::HashMap;

use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
use brokk_bifrost_analysis::analyzer::semantic::{IcfgEdgeKind, SemanticLocator};
use brokk_bifrost_flow::dataflow::{SummaryWitness, SummaryWitnessStepKind};
use serde::Serialize;

use crate::finding::PolicySourceLocation;
use crate::finding_identity::WitnessId;

const MAX_DISPLAY_PATH_ROWS: usize = 12;
const MAX_DISPLAY_LABEL_BYTES: usize = 160;
const TRUNCATED_LABEL_SUFFIX: &str = "...";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TaintDisplayStepKind {
    Source,
    Propagation,
    Call,
    Return,
    Sink,
}

impl TaintDisplayStepKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Propagation => "propagation",
            Self::Call => "call",
            Self::Return => "return",
            Self::Sink => "sink",
        }
    }

    const fn is_boundary(self) -> bool {
        matches!(self, Self::Call | Self::Return)
    }

    const fn information_rank(self) -> u8 {
        match self {
            Self::Source | Self::Sink => 4,
            Self::Call | Self::Return => 3,
            Self::Propagation => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub(crate) struct TaintDisplayStep {
    kind: TaintDisplayStepKind,
    location: PolicySourceLocation,
    label: String,
}

impl TaintDisplayStep {
    pub(crate) fn new(
        kind: TaintDisplayStepKind,
        location: PolicySourceLocation,
        label: impl AsRef<str>,
    ) -> Self {
        Self {
            kind,
            location,
            label: normalize_label(label.as_ref()),
        }
    }

    pub(crate) const fn kind(&self) -> TaintDisplayStepKind {
        self.kind
    }

    pub(crate) const fn location(&self) -> &PolicySourceLocation {
        &self.location
    }

    pub(crate) fn label(&self) -> &str {
        &self.label
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TaintDisplayPath {
    schema_version: u32,
    representative_witness_id: WitnessId,
    witness_ids: Vec<WitnessId>,
    steps: Vec<TaintDisplayStep>,
    canonical_incomplete: bool,
    omitted_meaningful_steps: u64,
    alternatives_truncated: bool,
    omitted_alternative_paths_lower_bound: u64,
    omitted_witnesses_lower_bound: u64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TaintDisplayPathCache(Option<Box<TaintDisplayPath>>);

impl TaintDisplayPathCache {
    pub(crate) fn get(&self) -> Option<&TaintDisplayPath> {
        self.0.as_deref()
    }

    pub(crate) fn attach(&mut self, path: Option<TaintDisplayPath>) {
        debug_assert!(self.0.is_none());
        self.0 = path.map(Box::new);
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.0.is_none()
    }
}

impl Serialize for TaintDisplayPathCache {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.get() {
            Some(path) => path.serialize(serializer),
            None => serializer.serialize_none(),
        }
    }
}

impl PartialEq for TaintDisplayPathCache {
    fn eq(&self, _other: &Self) -> bool {
        // Presentation data does not participate in canonical finding equality.
        true
    }
}

impl TaintDisplayPath {
    pub(crate) const SCHEMA_VERSION: u32 = 1;

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub(crate) fn steps(&self) -> &[TaintDisplayStep] {
        &self.steps
    }

    pub(crate) const fn witness_id(&self) -> &WitnessId {
        &self.representative_witness_id
    }

    pub(crate) fn witness_ids(&self) -> &[WitnessId] {
        &self.witness_ids
    }

    pub(crate) const fn canonical_incomplete(&self) -> bool {
        self.canonical_incomplete
    }

    pub(crate) const fn omitted_meaningful_steps(&self) -> u64 {
        self.omitted_meaningful_steps
    }

    pub(crate) const fn alternatives_truncated(&self) -> bool {
        self.alternatives_truncated
    }

    pub(crate) const fn omitted_alternative_paths_lower_bound(&self) -> u64 {
        self.omitted_alternative_paths_lower_bound
    }

    pub(crate) const fn omitted_witnesses_lower_bound(&self) -> u64 {
        self.omitted_witnesses_lower_bound
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        steps: Vec<TaintDisplayStep>,
        canonical_incomplete: bool,
        omitted_meaningful_steps: u64,
    ) -> Self {
        let witness_id = WitnessId::try_new("test", "display").unwrap();
        Self {
            schema_version: Self::SCHEMA_VERSION,
            representative_witness_id: witness_id.clone(),
            witness_ids: vec![witness_id],
            steps,
            canonical_incomplete,
            omitted_meaningful_steps,
            alternatives_truncated: false,
            omitted_alternative_paths_lower_bound: 0,
            omitted_witnesses_lower_bound: 0,
        }
    }
}

#[derive(Debug)]
pub(crate) struct TaintDisplayCandidate {
    path: TaintDisplayPath,
    complete_anchors: bool,
    informative_steps: usize,
    removed_noise: usize,
}

#[derive(Debug)]
struct RawDisplayStep {
    step: TaintDisplayStep,
    informative: bool,
}

pub(crate) fn project_taint_display_candidate(
    workspace: &WorkspaceAnalyzer,
    origin: &SemanticLocator,
    sink: &SemanticLocator,
    witness_id: WitnessId,
    witness: &SummaryWitness,
    finding_incomplete: bool,
) -> Result<TaintDisplayCandidate, String> {
    let origin_location = super::semantic_identity::policy_location(workspace, origin)?;
    let sink_location = super::semantic_identity::policy_location(workspace, sink)?;
    let origin_excerpt = super::semantic_identity::source_excerpt(workspace, origin)
        .filter(|excerpt| !excerpt.trim().is_empty());
    let sink_excerpt = super::semantic_identity::source_excerpt(workspace, sink)
        .filter(|excerpt| !excerpt.trim().is_empty());
    let complete_anchors = origin_excerpt.is_some() && sink_excerpt.is_some();
    let origin_label = origin_excerpt.unwrap_or_else(|| "taint source".to_owned());
    let sink_label = sink_excerpt.unwrap_or_else(|| "taint sink".to_owned());

    let mut intermediate = Vec::new();
    for step in witness.steps() {
        let projected = match step.kind() {
            SummaryWitnessStepKind::Seed => None,
            SummaryWitnessStepKind::Edge(IcfgEdgeKind::Call) => step.origin().map(|call| {
                let locator = super::semantic_identity::call_site_locator(call);
                raw_step(
                    workspace,
                    TaintDisplayStepKind::Call,
                    locator,
                    "call boundary",
                    true,
                )
            }),
            SummaryWitnessStepKind::Edge(
                IcfgEdgeKind::NormalReturn | IcfgEdgeKind::ExceptionalReturn,
            ) => step.origin().map(|call| {
                let locator = super::semantic_identity::call_site_locator(call);
                let excerpt = locator_label(workspace, locator, "call boundary");
                let label = format!("return from {excerpt}");
                RawDisplayStep {
                    step: TaintDisplayStep::new(
                        TaintDisplayStepKind::Return,
                        super::semantic_identity::policy_location(workspace, locator)
                            .expect("a previously projected semantic locator stays valid"),
                        label,
                    ),
                    informative: true,
                }
            }),
            SummaryWitnessStepKind::EndSummaryGap(_) => Some(raw_step(
                workspace,
                TaintDisplayStepKind::Return,
                super::semantic_identity::program_point_locator(step.source()),
                "taint summary boundary",
                true,
            )),
            SummaryWitnessStepKind::Edge(IcfgEdgeKind::Intraprocedural(_))
                if step.input_fact() != step.output_fact() =>
            {
                Some(raw_step(
                    workspace,
                    TaintDisplayStepKind::Propagation,
                    super::semantic_identity::program_point_locator(step.source()),
                    "taint propagation",
                    true,
                ))
            }
            SummaryWitnessStepKind::Edge(IcfgEdgeKind::Intraprocedural(_)) => None,
            SummaryWitnessStepKind::Edge(
                IcfgEdgeKind::CallToNormalContinuation
                | IcfgEdgeKind::CallToExceptionalContinuation,
            ) => None,
        };
        if let Some(projected) = projected {
            intermediate.push(projected);
        }
    }

    Ok(project_display_rows(
        witness_id,
        TaintDisplayStep::new(TaintDisplayStepKind::Source, origin_location, origin_label),
        intermediate,
        TaintDisplayStep::new(TaintDisplayStepKind::Sink, sink_location, sink_label),
        finding_incomplete || witness.truncated(),
        complete_anchors,
    ))
}

fn raw_step(
    workspace: &WorkspaceAnalyzer,
    kind: TaintDisplayStepKind,
    locator: &SemanticLocator,
    fallback: &'static str,
    informative: bool,
) -> RawDisplayStep {
    RawDisplayStep {
        step: TaintDisplayStep::new(
            kind,
            super::semantic_identity::policy_location(workspace, locator)
                .expect("a validated semantic locator has a policy location"),
            locator_label(workspace, locator, fallback),
        ),
        informative,
    }
}

fn locator_label(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
    fallback: &'static str,
) -> String {
    super::semantic_identity::source_excerpt(workspace, locator)
        .filter(|excerpt| !excerpt.trim().is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

fn project_display_rows(
    witness_id: WitnessId,
    source: TaintDisplayStep,
    intermediate: Vec<RawDisplayStep>,
    sink: TaintDisplayStep,
    canonical_incomplete: bool,
    complete_anchors: bool,
) -> TaintDisplayCandidate {
    let raw_count = intermediate.len();
    let mut deduplicated = Vec::<RawDisplayStep>::new();
    for candidate in intermediate {
        if !candidate.step.kind.is_boundary()
            && (candidate.step.location == source.location
                || candidate.step.location == sink.location)
        {
            continue;
        }
        if !candidate.step.kind.is_boundary()
            && (location_strictly_contains(&candidate.step.location, &source.location)
                || location_strictly_contains(&candidate.step.location, &sink.location))
        {
            continue;
        }
        if deduplicated.iter().any(|existing| {
            existing.step.kind == candidate.step.kind
                && existing.step.location == candidate.step.location
                && existing.step.label == candidate.step.label
        }) {
            continue;
        }
        if !candidate.informative
            && deduplicated
                .iter()
                .any(|existing| existing.step.location == candidate.step.location)
        {
            continue;
        }
        deduplicated.push(candidate);
    }

    let nested_keep = deduplicated
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            candidate.step.kind.is_boundary()
                || !deduplicated.iter().enumerate().any(|(other_index, other)| {
                    index != other_index
                        && location_strictly_contains(
                            &candidate.step.location,
                            &other.step.location,
                        )
                        && other.step.kind.information_rank()
                            >= candidate.step.kind.information_rank()
                })
        })
        .collect::<Vec<_>>();
    let mut meaningful = deduplicated
        .into_iter()
        .zip(nested_keep)
        .filter_map(|(row, keep)| keep.then_some(row))
        .collect::<Vec<_>>();

    let intermediate_limit = MAX_DISPLAY_PATH_ROWS.saturating_sub(2);
    let omitted_meaningful_steps = meaningful.len().saturating_sub(intermediate_limit);
    if omitted_meaningful_steps > 0 {
        let mut ranked = meaningful
            .iter()
            .enumerate()
            .map(|(index, row)| (index, row.step.kind.information_rank()))
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        ranked.truncate(intermediate_limit);
        ranked.sort_by_key(|(index, _)| *index);
        let selected = ranked
            .into_iter()
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        meaningful = meaningful
            .into_iter()
            .enumerate()
            .filter_map(|(index, row)| selected.binary_search(&index).ok().map(|_| row))
            .collect();
    }

    let informative_steps = meaningful.iter().filter(|row| row.informative).count();
    let removed_noise = raw_count.saturating_sub(meaningful.len());
    let mut steps = Vec::with_capacity(meaningful.len().saturating_add(2));
    steps.push(source);
    steps.extend(meaningful.into_iter().map(|row| row.step));
    steps.push(sink);
    TaintDisplayCandidate {
        path: TaintDisplayPath {
            schema_version: TaintDisplayPath::SCHEMA_VERSION,
            representative_witness_id: witness_id.clone(),
            witness_ids: vec![witness_id],
            steps,
            canonical_incomplete,
            omitted_meaningful_steps: u64::try_from(omitted_meaningful_steps).unwrap_or(u64::MAX),
            alternatives_truncated: false,
            omitted_alternative_paths_lower_bound: 0,
            omitted_witnesses_lower_bound: 0,
        },
        complete_anchors,
        informative_steps,
        removed_noise,
    }
}

fn location_strictly_contains(outer: &PolicySourceLocation, inner: &PolicySourceLocation) -> bool {
    if outer.path() != inner.path() {
        return false;
    }
    let (Some(outer), Some(inner)) = (outer.byte_span(), inner.byte_span()) else {
        return false;
    };
    outer.start() <= inner.start()
        && inner.end() <= outer.end()
        && (outer.start(), outer.end()) != (inner.start(), inner.end())
}

pub(crate) fn select_taint_display_path(
    candidates: impl IntoIterator<Item = TaintDisplayCandidate>,
    omitted_witnesses_lower_bound: u64,
) -> Option<TaintDisplayPath> {
    let mut groups = HashMap::<Vec<TaintDisplayStep>, TaintDisplayGroup>::new();
    for candidate in candidates {
        let signature = candidate.path.steps.clone();
        match groups.entry(signature) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let group = entry.get_mut();
                group
                    .witness_ids
                    .push(candidate.path.representative_witness_id.clone());
                if compare_candidates(&candidate, &group.representative).is_gt() {
                    group.representative = candidate;
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(TaintDisplayGroup {
                    witness_ids: vec![candidate.path.representative_witness_id.clone()],
                    representative: candidate,
                });
            }
        }
    }

    let omitted_alternative_paths_lower_bound =
        u64::try_from(groups.len().saturating_sub(1)).unwrap_or(u64::MAX);
    let mut selected = groups
        .into_values()
        .max_by(|left, right| compare_candidates(&left.representative, &right.representative))?;
    selected.witness_ids.sort();
    selected.witness_ids.dedup();
    let mut path = selected.representative.path;
    path.witness_ids = selected.witness_ids;
    path.alternatives_truncated = omitted_witnesses_lower_bound > 0;
    path.omitted_alternative_paths_lower_bound = omitted_alternative_paths_lower_bound;
    path.omitted_witnesses_lower_bound = omitted_witnesses_lower_bound;
    Some(path)
}

struct TaintDisplayGroup {
    representative: TaintDisplayCandidate,
    witness_ids: Vec<WitnessId>,
}

fn compare_candidates(left: &TaintDisplayCandidate, right: &TaintDisplayCandidate) -> Ordering {
    // Display quality order: complete anchors, complete canonical path, more
    // informative stages, less projection noise, fewer display omissions, and
    // finally the lexicographically smaller canonical witness identity.
    left.complete_anchors
        .cmp(&right.complete_anchors)
        .then_with(|| (!left.path.canonical_incomplete).cmp(&!right.path.canonical_incomplete))
        .then_with(|| left.informative_steps.cmp(&right.informative_steps))
        .then_with(|| right.removed_noise.cmp(&left.removed_noise))
        .then_with(|| {
            right
                .path
                .omitted_meaningful_steps
                .cmp(&left.path.omitted_meaningful_steps)
        })
        .then_with(|| {
            right
                .path
                .representative_witness_id
                .cmp(&left.path.representative_witness_id)
        })
}

fn normalize_label(label: &str) -> String {
    let mut normalized = String::new();
    let mut whitespace = false;
    for character in label.trim().chars() {
        if character.is_whitespace() {
            whitespace = !normalized.is_empty();
            continue;
        }
        if whitespace {
            normalized.push(' ');
            whitespace = false;
        }
        normalized.push(character);
    }
    if normalized.is_empty() {
        normalized.push('-');
    }
    if normalized.len() <= MAX_DISPLAY_LABEL_BYTES {
        return normalized;
    }
    let mut boundary = MAX_DISPLAY_LABEL_BYTES.saturating_sub(TRUNCATED_LABEL_SUFFIX.len());
    while !normalized.is_char_boundary(boundary) {
        boundary -= 1;
    }
    normalized.truncate(boundary);
    normalized.push_str(TRUNCATED_LABEL_SUFFIX);
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{PolicyByteSpan, PolicyDisplayRegion};
    use brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath;

    fn location(start: u64, end: u64) -> PolicySourceLocation {
        PolicySourceLocation::span(
            WorkspaceRelativePath::new("src/Foo.java").unwrap(),
            PolicyByteSpan::new(start, end).unwrap(),
            PolicyDisplayRegion::new(1, start + 1, 1, end + 1).unwrap(),
        )
    }

    fn step(
        kind: TaintDisplayStepKind,
        start: u64,
        end: u64,
        label: &str,
        informative: bool,
    ) -> RawDisplayStep {
        RawDisplayStep {
            step: TaintDisplayStep::new(kind, location(start, end), label),
            informative,
        }
    }

    #[test]
    fn projection_collapses_duplicates_and_nested_noise_but_keeps_boundaries() {
        let candidate = project_display_rows(
            WitnessId::try_new("test", "better").unwrap(),
            TaintDisplayStep::new(TaintDisplayStepKind::Source, location(20, 30), "source()"),
            vec![
                step(TaintDisplayStepKind::Propagation, 10, 40, "method", false),
                step(TaintDisplayStepKind::Call, 40, 50, "relay(source())", true),
                step(TaintDisplayStepKind::Call, 40, 50, "relay(source())", true),
                step(
                    TaintDisplayStepKind::Return,
                    40,
                    50,
                    "return from relay(source())",
                    true,
                ),
                step(
                    TaintDisplayStepKind::Return,
                    60,
                    70,
                    "taint summary boundary",
                    true,
                ),
            ],
            TaintDisplayStep::new(TaintDisplayStepKind::Sink, location(60, 70), "sink(...)"),
            true,
            true,
        );
        let rows = candidate.path.steps();
        assert_eq!(
            rows.iter().map(TaintDisplayStep::kind).collect::<Vec<_>>(),
            vec![
                TaintDisplayStepKind::Source,
                TaintDisplayStepKind::Call,
                TaintDisplayStepKind::Return,
                TaintDisplayStepKind::Return,
                TaintDisplayStepKind::Sink,
            ]
        );
        assert!(candidate.path.canonical_incomplete());
        assert_eq!(candidate.path.omitted_meaningful_steps(), 0);
    }

    #[test]
    fn selection_uses_quality_then_stable_canonical_identity() {
        let make =
            |id: &str, informative, removed_noise, canonical_incomplete| TaintDisplayCandidate {
                path: TaintDisplayPath {
                    schema_version: TaintDisplayPath::SCHEMA_VERSION,
                    representative_witness_id: WitnessId::try_new("test", id).unwrap(),
                    witness_ids: vec![WitnessId::try_new("test", id).unwrap()],
                    steps: vec![
                        TaintDisplayStep::new(
                            TaintDisplayStepKind::Source,
                            location(0, 1),
                            "source()",
                        ),
                        TaintDisplayStep::new(TaintDisplayStepKind::Sink, location(2, 3), "sink()"),
                    ],
                    canonical_incomplete,
                    omitted_meaningful_steps: 0,
                    alternatives_truncated: false,
                    omitted_alternative_paths_lower_bound: 0,
                    omitted_witnesses_lower_bound: 0,
                },
                complete_anchors: true,
                informative_steps: informative,
                removed_noise,
            };
        let selected =
            select_taint_display_path(vec![make("z", 1, 0, false), make("a", 4, 0, true)], 0)
                .expect("one candidate");
        assert_eq!(selected.witness_id().as_str(), "test:z");

        let selected =
            select_taint_display_path(vec![make("z", 1, 0, false), make("a", 2, 3, false)], 0)
                .expect("one candidate");
        assert_eq!(selected.witness_id().as_str(), "test:a");

        let selected =
            select_taint_display_path(vec![make("z", 2, 0, false), make("a", 2, 0, false)], 0)
                .expect("one candidate");
        assert_eq!(selected.witness_id().as_str(), "test:a");
        let selected =
            select_taint_display_path(vec![make("a", 2, 0, false), make("z", 2, 0, false)], 0)
                .expect("one candidate");
        assert_eq!(selected.witness_id().as_str(), "test:a");
    }

    #[test]
    fn selection_groups_identical_rows_and_keeps_honest_provenance() {
        let make = |id: &str, sink_start: u64| TaintDisplayCandidate {
            path: TaintDisplayPath {
                schema_version: TaintDisplayPath::SCHEMA_VERSION,
                representative_witness_id: WitnessId::try_new("test", id).unwrap(),
                witness_ids: vec![WitnessId::try_new("test", id).unwrap()],
                steps: vec![
                    TaintDisplayStep::new(TaintDisplayStepKind::Source, location(0, 1), "source()"),
                    TaintDisplayStep::new(
                        TaintDisplayStepKind::Sink,
                        location(sink_start, sink_start + 1),
                        "sink()",
                    ),
                ],
                canonical_incomplete: false,
                omitted_meaningful_steps: 0,
                alternatives_truncated: false,
                omitted_alternative_paths_lower_bound: 0,
                omitted_witnesses_lower_bound: 0,
            },
            complete_anchors: true,
            informative_steps: 2,
            removed_noise: 0,
        };
        let selected =
            select_taint_display_path(vec![make("z", 2), make("a", 2), make("other", 4)], 3)
                .expect("one selected display path");

        assert_eq!(selected.witness_id().as_str(), "test:a");
        assert_eq!(
            selected
                .witness_ids()
                .iter()
                .map(WitnessId::as_str)
                .collect::<Vec<_>>(),
            vec!["test:a", "test:z"]
        );
        assert_eq!(selected.omitted_alternative_paths_lower_bound(), 1);
        assert!(selected.alternatives_truncated());
        assert_eq!(selected.omitted_witnesses_lower_bound(), 3);
    }

    #[test]
    fn projection_bounds_meaningful_rows_without_changing_flow_order() {
        let intermediate = (0..14)
            .map(|index| {
                step(
                    TaintDisplayStepKind::Call,
                    10 + index * 2,
                    11 + index * 2,
                    &format!("call{index}()"),
                    true,
                )
            })
            .collect();
        let candidate = project_display_rows(
            WitnessId::try_new("test", "bounded").unwrap(),
            TaintDisplayStep::new(TaintDisplayStepKind::Source, location(0, 1), "source()"),
            intermediate,
            TaintDisplayStep::new(TaintDisplayStepKind::Sink, location(100, 101), "sink()"),
            false,
            true,
        );
        assert_eq!(candidate.path.steps().len(), MAX_DISPLAY_PATH_ROWS);
        assert_eq!(candidate.path.omitted_meaningful_steps(), 4);
        assert_eq!(candidate.path.steps()[1].label(), "call0()");
        assert_eq!(candidate.path.steps()[10].label(), "call9()");
    }

    #[test]
    fn labels_are_single_line_terminal_preserving_and_utf8_bounded() {
        let label = normalize_label(&format!("  source\n\t\u{1b}{}  ", "é".repeat(100)));
        assert!(label.starts_with("source \u{1b}"));
        assert!(!label.contains('\n'));
        assert!(label.len() <= MAX_DISPLAY_LABEL_BYTES);
        assert!(label.ends_with(TRUNCATED_LABEL_SUFFIX));
    }
}
