//! Source-backed assertions for inline semantic control-flow fixtures.
//!
//! The harness intentionally keeps dense semantic IDs behind readable aliases.
//! Selectors scan only the test fixture source, then resolve matching program
//! points through the artifact's source mappings.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::{self, Write as _};
use std::path::Path;
use std::sync::Arc;

use brokk_bifrost::WorkspaceAnalyzer;
use brokk_bifrost::analyzer::semantic::{
    CancellationToken, ControlEdgeKind, ProcedureId, ProcedureSemantics, ProgramPoint,
    ProgramPointId, SemanticArtifact, SemanticBudget, SemanticEffect, SemanticOutcome,
    SemanticRequest, SourceAnchor, SourceMappingId, SourceSpan,
};

use super::BuiltInlineTestProject;

const MAX_ERROR_CANDIDATES: usize = 16;
const MAX_ERROR_TOPOLOGY_LINES: usize = 80;

/// A readable, source-backed program-point selector.
///
/// `occurrence` is zero-based among textual occurrences of `substring` in the
/// fixture file. `anchor_occurrence` is the independent occurrence carried by
/// a [`SourceAnchor`] when lowering specializes the same syntax more than once
/// (for example, a `finally` body reached by multiple completion routes). The
/// remaining qualifiers are applied to semantic points after source-mapping
/// resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointSelector {
    substring: Box<str>,
    procedure: Option<Box<str>>,
    effect: Option<Box<str>>,
    outgoing_kind: Option<ControlEdgeKind>,
    occurrence: Option<usize>,
    anchor_occurrence: Option<u32>,
}

impl PointSelector {
    pub fn new(substring: impl Into<String>) -> Self {
        Self {
            substring: substring.into().into_boxed_str(),
            procedure: None,
            effect: None,
            outgoing_kind: None,
            occurrence: None,
            anchor_occurrence: None,
        }
    }

    /// Restrict the match to a callable's readable declaration path or final
    /// named declaration segment.
    pub fn procedure(mut self, procedure: impl Into<String>) -> Self {
        self.procedure = Some(procedure.into().into_boxed_str());
        self
    }

    /// Restrict the match to a point containing an effect with this stable
    /// [`SemanticEffect::label`] value, such as `entry`, `invoke`, or `throw`.
    pub fn effect(mut self, effect: impl Into<String>) -> Self {
        self.effect = Some(effect.into().into_boxed_str());
        self
    }

    /// Restrict the match to a point with at least one outgoing edge of `kind`.
    pub const fn outgoing_kind(mut self, kind: ControlEdgeKind) -> Self {
        self.outgoing_kind = Some(kind);
        self
    }

    /// Select a zero-based textual occurrence of the source substring.
    pub const fn occurrence(mut self, occurrence: usize) -> Self {
        self.occurrence = Some(occurrence);
        self
    }

    /// Select a source mapping's zero-based semantic anchor occurrence.
    ///
    /// This does not change which textual occurrence of `substring` is used;
    /// combine it with [`Self::occurrence`] when both dimensions are needed.
    pub const fn anchor_occurrence(mut self, occurrence: u32) -> Self {
        self.anchor_occurrence = Some(occurrence);
        self
    }
}

impl From<&str> for PointSelector {
    fn from(substring: &str) -> Self {
        Self::new(substring)
    }
}

impl From<String> for PointSelector {
    fn from(substring: String) -> Self {
        Self::new(substring)
    }
}

/// One expected adjacent CFG edge. For successors `endpoint` is the target;
/// for predecessors it is the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedEdge<'alias> {
    pub endpoint: &'alias str,
    pub kind: ControlEdgeKind,
}

impl<'alias> ExpectedEdge<'alias> {
    pub const fn new(endpoint: &'alias str, kind: ControlEdgeKind) -> Self {
        Self { endpoint, kind }
    }
}

/// Shorthand for readable edge expectations.
pub const fn edge(endpoint: &str, kind: ControlEdgeKind) -> ExpectedEdge<'_> {
    ExpectedEdge::new(endpoint, kind)
}

/// Bounds for the deterministic, ID-free topology renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopologyRenderLimits {
    pub max_procedures: usize,
    pub max_points: usize,
    pub max_edges: usize,
    pub max_output_bytes: usize,
}

impl Default for TopologyRenderLimits {
    fn default() -> Self {
        Self {
            max_procedures: 64,
            max_points: 2_048,
            max_edges: 4_096,
            max_output_bytes: 256 * 1024,
        }
    }
}

/// Failure to materialize or source-resolve a semantic graph fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticGraphError {
    detail: Box<str>,
}

impl SemanticGraphError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into().into_boxed_str(),
        }
    }
}

impl fmt::Display for SemanticGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for SemanticGraphError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct BoundPoint {
    procedure: ProcedureId,
    point: ProgramPointId,
}

#[derive(Debug, Clone, Copy)]
struct Candidate {
    bound: BoundPoint,
    anchor: SourceAnchor,
    exact: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ComparableEdge {
    endpoint: ProgramPointId,
    kind: &'static str,
}

/// A materialized per-file semantic artifact plus readable CFG aliases.
pub struct SemanticGraph {
    artifact: Arc<SemanticArtifact>,
    source: String,
    aliases: HashMap<Box<str>, BoundPoint>,
}

impl SemanticGraph {
    /// Materialize one inline fixture file with a default semantic budget.
    pub fn materialize(
        project: &BuiltInlineTestProject,
        analyzer: &WorkspaceAnalyzer,
        relative_path: impl AsRef<Path>,
    ) -> Self {
        let mut budget = SemanticBudget::default();
        let cancellation = CancellationToken::default();
        Self::try_materialize_with_request(
            project,
            analyzer,
            relative_path,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap_or_else(|error| panic!("failed to materialize semantic graph fixture: {error}"))
    }

    /// Materialize one inline fixture file with caller-owned request controls.
    pub fn try_materialize_with_request(
        project: &BuiltInlineTestProject,
        analyzer: &WorkspaceAnalyzer,
        relative_path: impl AsRef<Path>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Self, SemanticGraphError> {
        let file = project.file(relative_path);
        let source = file.read_to_string().map_err(|error| {
            SemanticGraphError::new(format!(
                "failed to read inline semantic fixture {}: {error}",
                file.rel_path().display()
            ))
        })?;
        let outcome = analyzer
            .materialize_program_semantics(&file, request)
            .map_err(|error| SemanticGraphError::new(error.to_string()))?;
        let artifact = match outcome {
            SemanticOutcome::Complete { value, .. } => value,
            SemanticOutcome::Ambiguous { .. } => {
                return Err(SemanticGraphError::new(
                    "semantic fixture materialization was ambiguous",
                ));
            }
            SemanticOutcome::Unknown { .. } => {
                return Err(SemanticGraphError::new(
                    "semantic fixture materialization was unknown",
                ));
            }
            SemanticOutcome::Unsupported { capability, .. } => {
                return Err(SemanticGraphError::new(format!(
                    "semantic fixture materialization does not support {}",
                    capability.label()
                )));
            }
            SemanticOutcome::Unproven { .. } => {
                return Err(SemanticGraphError::new(
                    "semantic fixture materialization was unproven",
                ));
            }
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                return Err(SemanticGraphError::new(format!(
                    "semantic fixture materialization exceeded its budget: {exceeded}"
                )));
            }
            SemanticOutcome::Cancelled { .. } => {
                return Err(SemanticGraphError::new(
                    "semantic fixture materialization was cancelled",
                ));
            }
        };
        Ok(Self {
            artifact,
            source,
            aliases: HashMap::new(),
        })
    }

    pub fn artifact(&self) -> &Arc<SemanticArtifact> {
        &self.artifact
    }

    /// Bind `alias` to exactly one source-backed program point.
    ///
    /// Ambiguous and missing selectors panic with candidate source spans and a
    /// bounded, deterministic topology excerpt. Use [`Self::try_bind`] when a
    /// test needs to inspect resolution failure explicitly.
    pub fn bind(
        &mut self,
        alias: impl Into<String>,
        selector: impl Into<PointSelector>,
    ) -> &mut Self {
        let alias = alias.into();
        self.try_bind(alias.clone(), selector)
            .unwrap_or_else(|error| panic!("failed to bind semantic alias {alias:?}: {error}"));
        self
    }

    pub fn try_bind(
        &mut self,
        alias: impl Into<String>,
        selector: impl Into<PointSelector>,
    ) -> Result<(), SemanticGraphError> {
        let alias = alias.into();
        if alias.is_empty() {
            return Err(SemanticGraphError::new(
                "semantic graph aliases must not be empty",
            ));
        }
        if self.aliases.contains_key(alias.as_str()) {
            return Err(SemanticGraphError::new(format!(
                "semantic graph alias {alias:?} is already bound"
            )));
        }
        let selector = selector.into();
        let candidates = self.resolve_candidates(&selector)?;
        if candidates.len() != 1 {
            return Err(self.selector_error(&selector, &candidates));
        }
        self.aliases
            .insert(alias.into_boxed_str(), candidates[0].bound);
        Ok(())
    }

    pub fn assert_successors(&self, alias: &str, expected_edges: &[ExpectedEdge<'_>]) {
        self.assert_edges(alias, expected_edges, EdgeDirection::Successors);
    }

    pub fn assert_predecessors(&self, alias: &str, expected_edges: &[ExpectedEdge<'_>]) {
        self.assert_edges(alias, expected_edges, EdgeDirection::Predecessors);
    }

    /// Verify that each canonical edge occurs in both directional adjacency
    /// views with the same edge identity and payload.
    pub fn assert_adjacency_symmetric(&self) {
        for procedure in self.artifact.procedures() {
            for point in procedure.points() {
                for (edge_id, edge) in procedure.successor_edges(point.id) {
                    if !procedure.predecessor_edges(edge.target_point).any(
                        |(candidate_id, candidate)| candidate_id == edge_id && candidate == edge,
                    ) {
                        panic!(
                            "successor adjacency is not mirrored for {} -{}-> {}\n\n{}",
                            self.point_name(procedure, edge.source_point),
                            edge.kind.label(),
                            self.point_name(procedure, edge.target_point),
                            self.render_topology_excerpt(MAX_ERROR_TOPOLOGY_LINES)
                        );
                    }
                }
                for (edge_id, edge) in procedure.predecessor_edges(point.id) {
                    if !procedure.successor_edges(edge.source_point).any(
                        |(candidate_id, candidate)| candidate_id == edge_id && candidate == edge,
                    ) {
                        panic!(
                            "predecessor adjacency is not mirrored for {} -{}-> {}\n\n{}",
                            self.point_name(procedure, edge.source_point),
                            edge.kind.label(),
                            self.point_name(procedure, edge.target_point),
                            self.render_topology_excerpt(MAX_ERROR_TOPOLOGY_LINES)
                        );
                    }
                }
            }
        }
    }

    pub fn assert_reachable(&self, from: &str, to: &str) {
        self.assert_reachability(from, to, true);
    }

    pub fn assert_unreachable(&self, from: &str, to: &str) {
        self.assert_reachability(from, to, false);
    }

    /// Render a deterministic, source-backed CFG view that never exposes raw
    /// dense procedure, point, edge, source-mapping, or evidence IDs.
    pub fn render_topology(&self) -> String {
        self.render_topology_with_limits(TopologyRenderLimits::default())
    }

    pub fn render_topology_with_limits(&self, limits: TopologyRenderLimits) -> String {
        let mut writer = BoundedTopologyWriter::new(limits.max_output_bytes);
        let mut procedures = self.artifact.procedures().iter().collect::<Vec<_>>();
        procedures.sort_unstable_by_key(|procedure| self.procedure_label(procedure));
        let mut rendered_points = 0usize;
        let mut rendered_edges = 0usize;

        for procedure in procedures.into_iter().take(limits.max_procedures) {
            if !writer.line(&format!(
                "procedure {} kind={}",
                self.procedure_label(procedure),
                procedure.kind().label()
            )) {
                break;
            }
            let mut points = procedure.points().iter().collect::<Vec<_>>();
            points.sort_unstable_by_key(|point| self.point_descriptor(procedure, point.id));
            for point in points {
                if rendered_points >= limits.max_points {
                    writer.truncate("point limit reached");
                    break;
                }
                rendered_points += 1;
                let descriptor = self.point_descriptor(procedure, point.id);
                let aliases = self.aliases_for(BoundPoint {
                    procedure: procedure.id(),
                    point: point.id,
                });
                let alias_suffix = if aliases.is_empty() {
                    String::new()
                } else {
                    format!(" aliases={}", aliases.join(","))
                };
                if !writer.line(&format!(
                    "  {descriptor}{alias_suffix} `{}`",
                    self.snippet(self.point_anchor(procedure, point.id).span())
                )) {
                    break;
                }

                let mut edges = procedure.successor_edges(point.id).collect::<Vec<_>>();
                edges.sort_unstable_by_key(|(_, edge)| {
                    (
                        edge.kind.label(),
                        self.point_descriptor(procedure, edge.target_point),
                        self.mapping_span(procedure, edge.source),
                    )
                });
                for (_, edge) in edges {
                    if rendered_edges >= limits.max_edges {
                        writer.truncate("edge limit reached");
                        break;
                    }
                    rendered_edges += 1;
                    let provenance = self.mapping_span(procedure, edge.source);
                    if !writer.line(&format!(
                        "    -> {} {} source={}",
                        edge.kind.label(),
                        self.point_descriptor(procedure, edge.target_point),
                        format_span(provenance)
                    )) {
                        break;
                    }
                }
                if writer.truncated {
                    break;
                }
            }
            if writer.truncated {
                break;
            }
        }
        if self.artifact.procedures().len() > limits.max_procedures && !writer.truncated {
            writer.truncate("procedure limit reached");
        }
        writer.finish()
    }

    pub fn assert_topology(&self, expected: &str) {
        let actual = self.render_topology();
        if normalize_topology(expected) != normalize_topology(&actual) {
            panic!("semantic topology mismatch\n\nexpected:\n{expected}\n\nactual:\n{actual}");
        }
    }

    fn resolve_candidates(
        &self,
        selector: &PointSelector,
    ) -> Result<Vec<Candidate>, SemanticGraphError> {
        if selector.substring.is_empty() {
            return Err(SemanticGraphError::new(
                "semantic point selector substring must not be empty",
            ));
        }
        let mut occurrences = self
            .source
            .match_indices(selector.substring.as_ref())
            .map(|(start, value)| start..start + value.len())
            .collect::<Vec<_>>();
        if let Some(occurrence) = selector.occurrence {
            let selected = occurrences.get(occurrence).cloned().ok_or_else(|| {
                SemanticGraphError::new(format!(
                    "source substring {:?} has {} occurrence(s), so occurrence {} does not exist",
                    selector.substring,
                    occurrences.len(),
                    occurrence
                ))
            })?;
            occurrences.clear();
            occurrences.push(selected);
        }
        if occurrences.is_empty() {
            return Err(SemanticGraphError::new(format!(
                "source substring {:?} does not occur in the fixture",
                selector.substring
            )));
        }

        let mut candidates: HashMap<BoundPoint, (SourceAnchor, bool)> = HashMap::new();
        for procedure in self.artifact.procedures() {
            if !self.procedure_matches(procedure, selector.procedure.as_deref()) {
                continue;
            }
            for point in procedure.points() {
                if point_is_boundary(point) && !selector_selects_boundary(selector) {
                    continue;
                }
                if !self.effect_matches(point, selector.effect.as_deref()) {
                    continue;
                }
                if selector.outgoing_kind.is_some_and(|kind| {
                    !procedure
                        .successor_edges(point.id)
                        .any(|(_, edge)| edge.kind == kind)
                }) {
                    continue;
                }
                let mut mappings = Vec::with_capacity(point.events.len() + 1);
                mappings.push(point.source);
                mappings.extend(point.events.iter().map(|event| event.source));
                for mapping in mappings {
                    let anchor = self.mapping_anchor(procedure, mapping);
                    if selector
                        .anchor_occurrence
                        .is_some_and(|occurrence| anchor.occurrence() != occurrence)
                    {
                        continue;
                    }
                    let exact = occurrences.iter().any(|occurrence| {
                        anchor.span().start_byte() as usize == occurrence.start
                            && anchor.span().end_byte() as usize == occurrence.end
                    });
                    if exact
                        || occurrences.iter().any(|occurrence| {
                            let start = anchor.span().start_byte() as usize;
                            let end = anchor.span().end_byte() as usize;
                            (start <= occurrence.start && end >= occurrence.end)
                                || (occurrence.start <= start && occurrence.end >= end)
                        })
                    {
                        candidates
                            .entry(BoundPoint {
                                procedure: procedure.id(),
                                point: point.id,
                            })
                            .and_modify(|existing| {
                                if (exact && !existing.1)
                                    || (exact == existing.1
                                        && span_width(anchor.span())
                                            < span_width(existing.0.span()))
                                {
                                    *existing = (anchor, exact);
                                }
                            })
                            .or_insert((anchor, exact));
                    }
                }
            }
        }

        let mut candidates = candidates
            .into_iter()
            .map(|(bound, (anchor, exact))| Candidate {
                bound,
                anchor,
                exact,
            })
            .collect::<Vec<_>>();
        if candidates.iter().any(|candidate| candidate.exact) {
            candidates.retain(|candidate| candidate.exact);
        }
        candidates.sort_unstable_by_key(|candidate| {
            let procedure = self.procedure(candidate.bound.procedure);
            (
                self.procedure_label(procedure),
                candidate.anchor,
                self.point_descriptor(procedure, candidate.bound.point),
            )
        });
        Ok(candidates)
    }

    fn selector_error(
        &self,
        selector: &PointSelector,
        candidates: &[Candidate],
    ) -> SemanticGraphError {
        let mut detail = String::new();
        let outcome = if candidates.is_empty() {
            "matched no semantic program point"
        } else {
            "matched more than one semantic program point"
        };
        let _ = writeln!(
            detail,
            "selector {:?} {outcome}; add a procedure, effect, outgoing-kind, textual occurrence, or anchor-occurrence qualifier",
            selector.substring
        );
        if !candidates.is_empty() {
            detail.push_str("candidates:\n");
            for candidate in candidates.iter().take(MAX_ERROR_CANDIDATES) {
                let procedure = self.procedure(candidate.bound.procedure);
                let _ = writeln!(
                    detail,
                    "  - {} :: {} anchor={} `{}`",
                    self.procedure_label(procedure),
                    self.point_descriptor(procedure, candidate.bound.point),
                    format_anchor(candidate.anchor),
                    self.snippet(candidate.anchor.span())
                );
            }
            if candidates.len() > MAX_ERROR_CANDIDATES {
                let _ = writeln!(
                    detail,
                    "  ... {} more candidate(s)",
                    candidates.len() - MAX_ERROR_CANDIDATES
                );
            }
        }
        detail.push_str("bounded topology context:\n");
        detail.push_str(&self.render_topology_excerpt(MAX_ERROR_TOPOLOGY_LINES));
        SemanticGraphError::new(detail)
    }

    fn assert_edges(
        &self,
        alias: &str,
        expected_edges: &[ExpectedEdge<'_>],
        direction: EdgeDirection,
    ) {
        let bound = self.bound(alias);
        let procedure = self.procedure(bound.procedure);
        let mut expected = expected_edges
            .iter()
            .map(|expected| {
                let endpoint = self.bound(expected.endpoint);
                if endpoint.procedure != bound.procedure {
                    panic!(
                        "CFG adjacency assertion crosses procedures: {alias:?} belongs to {}, but {:?} belongs to {}",
                        self.procedure_label(procedure),
                        expected.endpoint,
                        self.procedure_label(self.procedure(endpoint.procedure))
                    );
                }
                ComparableEdge {
                    endpoint: endpoint.point,
                    kind: expected.kind.label(),
                }
            })
            .collect::<Vec<_>>();
        let mut actual = match direction {
            EdgeDirection::Successors => procedure
                .successor_edges(bound.point)
                .map(|(_, edge)| ComparableEdge {
                    endpoint: edge.target_point,
                    kind: edge.kind.label(),
                })
                .collect::<Vec<_>>(),
            EdgeDirection::Predecessors => procedure
                .predecessor_edges(bound.point)
                .map(|(_, edge)| ComparableEdge {
                    endpoint: edge.source_point,
                    kind: edge.kind.label(),
                })
                .collect::<Vec<_>>(),
        };
        expected.sort_unstable();
        actual.sort_unstable();
        if actual != expected {
            panic!(
                "{} mismatch for alias {alias:?} ({})\nexpected:\n{}actual:\n{}\n{}",
                direction.label(),
                self.point_name(procedure, bound.point),
                self.format_comparable_edges(procedure, &expected),
                self.format_comparable_edges(procedure, &actual),
                self.render_topology_excerpt(MAX_ERROR_TOPOLOGY_LINES)
            );
        }
    }

    fn assert_reachability(&self, from: &str, to: &str, expected: bool) {
        let from = self.bound(from);
        let to = self.bound(to);
        if from.procedure != to.procedure {
            panic!("intraprocedural reachability aliases must belong to the same procedure");
        }
        let procedure = self.procedure(from.procedure);
        let mut queue = VecDeque::from([from.point]);
        let mut visited = HashSet::from([from.point]);
        while let Some(point) = queue.pop_front() {
            for (_, edge) in procedure.successor_edges(point) {
                if visited.insert(edge.target_point) {
                    queue.push_back(edge.target_point);
                }
            }
        }
        let actual = visited.contains(&to.point);
        if actual != expected {
            let relation = if expected { "reachable" } else { "unreachable" };
            panic!(
                "expected {} to be {relation} from {}\n\n{}",
                self.point_name(procedure, to.point),
                self.point_name(procedure, from.point),
                self.render_topology_excerpt(MAX_ERROR_TOPOLOGY_LINES)
            );
        }
    }

    fn format_comparable_edges(
        &self,
        procedure: &ProcedureSemantics,
        edges: &[ComparableEdge],
    ) -> String {
        if edges.is_empty() {
            return "  (none)\n".into();
        }
        let mut rendered = String::new();
        for edge in edges {
            let _ = writeln!(
                rendered,
                "  -{}-> {}",
                edge.kind,
                self.point_name(procedure, edge.endpoint)
            );
        }
        rendered
    }

    fn procedure_matches(&self, procedure: &ProcedureSemantics, qualifier: Option<&str>) -> bool {
        let Some(qualifier) = qualifier else {
            return true;
        };
        if self.procedure_label(procedure) == qualifier {
            return true;
        }
        procedure
            .locator()
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name())
            == Some(qualifier)
    }

    fn effect_matches(&self, point: &ProgramPoint, qualifier: Option<&str>) -> bool {
        qualifier.is_none_or(|qualifier| {
            point
                .events
                .iter()
                .any(|event| event.effect.label() == qualifier)
        })
    }

    fn bound(&self, alias: &str) -> BoundPoint {
        self.aliases
            .get(alias)
            .copied()
            .unwrap_or_else(|| panic!("semantic graph alias {alias:?} is not bound"))
    }

    fn procedure(&self, id: ProcedureId) -> &ProcedureSemantics {
        self.artifact
            .procedure(id)
            .expect("bound semantic procedure must remain in its artifact")
    }

    fn aliases_for(&self, bound: BoundPoint) -> Vec<&str> {
        let mut aliases = self
            .aliases
            .iter()
            .filter_map(|(alias, candidate)| (*candidate == bound).then_some(alias.as_ref()))
            .collect::<Vec<_>>();
        aliases.sort_unstable();
        aliases
    }

    fn point_name(&self, procedure: &ProcedureSemantics, point: ProgramPointId) -> String {
        let aliases = self.aliases_for(BoundPoint {
            procedure: procedure.id(),
            point,
        });
        if aliases.is_empty() {
            self.point_descriptor(procedure, point)
        } else {
            aliases
                .into_iter()
                .map(|alias| format!("${alias}"))
                .collect::<Vec<_>>()
                .join("|")
        }
    }

    fn point_descriptor(&self, procedure: &ProcedureSemantics, point: ProgramPointId) -> String {
        let point = procedure
            .point(point)
            .expect("semantic point must remain in its procedure");
        let effects = if point.events.is_empty() {
            "point".into()
        } else {
            point
                .events
                .iter()
                .map(|event| effect_descriptor(&event.effect))
                .collect::<Vec<_>>()
                .join("+")
        };
        let anchor = self.point_anchor(procedure, point.id);
        format!("{effects}@{}", format_anchor(anchor))
    }

    fn procedure_label(&self, procedure: &ProcedureSemantics) -> String {
        let mut label = procedure.locator().path().as_str().to_owned();
        for segment in procedure.locator().declaration().segments() {
            if matches!(
                segment.kind(),
                brokk_bifrost::analyzer::semantic::DeclarationSegmentKind::File
            ) {
                continue;
            }
            label.push_str("::");
            label.push_str(declaration_kind_label(segment.kind()));
            label.push(':');
            match segment.name() {
                Some(name) => label.push_str(name),
                None => label.push_str(&format!("anonymous@{}", format_anchor(segment.anchor()))),
            }
            if segment.sibling_ordinal() > 0 {
                let _ = write!(label, "#{}", segment.sibling_ordinal());
            }
        }
        label
    }

    fn point_anchor(&self, procedure: &ProcedureSemantics, point: ProgramPointId) -> SourceAnchor {
        let point = procedure
            .point(point)
            .expect("semantic point must remain in its procedure");
        self.mapping_anchor(procedure, point.source)
    }

    fn mapping_anchor(
        &self,
        procedure: &ProcedureSemantics,
        source: SourceMappingId,
    ) -> SourceAnchor {
        procedure
            .source_mapping(source)
            .expect("validated semantic source mapping must exist")
            .locator
            .anchor()
    }

    fn mapping_span(&self, procedure: &ProcedureSemantics, source: SourceMappingId) -> SourceSpan {
        self.mapping_anchor(procedure, source).span()
    }

    fn snippet(&self, span: SourceSpan) -> String {
        let Some(source) = self
            .source
            .get(span.start_byte() as usize..span.end_byte() as usize)
        else {
            return "<invalid source span>".into();
        };
        let single_line = source.split_whitespace().collect::<Vec<_>>().join(" ");
        truncate_chars(&single_line, 72)
    }

    fn render_topology_excerpt(&self, max_lines: usize) -> String {
        let topology = self.render_topology();
        let mut lines = topology.lines();
        let excerpt = lines
            .by_ref()
            .take(max_lines)
            .collect::<Vec<_>>()
            .join("\n");
        if lines.next().is_some() {
            format!("{excerpt}\n... (topology excerpt truncated)\n")
        } else if excerpt.is_empty() {
            excerpt
        } else {
            format!("{excerpt}\n")
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum EdgeDirection {
    Successors,
    Predecessors,
}

impl EdgeDirection {
    const fn label(self) -> &'static str {
        match self {
            Self::Successors => "successor adjacency",
            Self::Predecessors => "predecessor adjacency",
        }
    }
}

struct BoundedTopologyWriter {
    output: String,
    max_output_bytes: usize,
    truncated: bool,
}

impl BoundedTopologyWriter {
    fn new(max_output_bytes: usize) -> Self {
        Self {
            output: String::new(),
            max_output_bytes,
            truncated: false,
        }
    }

    fn line(&mut self, line: &str) -> bool {
        if self.truncated {
            return false;
        }
        let required = line.len().saturating_add(1);
        if self.output.len().saturating_add(required) > self.max_output_bytes {
            self.truncate("output byte limit reached");
            return false;
        }
        self.output.push_str(line);
        self.output.push('\n');
        true
    }

    fn truncate(&mut self, reason: &str) {
        if self.truncated {
            return;
        }
        self.truncated = true;
        let marker = format!("... (truncated: {reason})\n");
        if self.output.len().saturating_add(marker.len()) <= self.max_output_bytes {
            self.output.push_str(&marker);
        }
    }

    fn finish(self) -> String {
        self.output
    }
}

fn effect_descriptor(effect: &SemanticEffect) -> &'static str {
    effect.label()
}

fn selector_selects_boundary(selector: &PointSelector) -> bool {
    matches!(
        selector.effect.as_deref(),
        Some("entry" | "normal_exit" | "exceptional_exit")
    )
}

fn point_is_boundary(point: &ProgramPoint) -> bool {
    point.events.iter().any(|event| {
        matches!(
            event.effect,
            SemanticEffect::Entry | SemanticEffect::NormalExit | SemanticEffect::ExceptionalExit
        )
    })
}

fn declaration_kind_label(
    kind: brokk_bifrost::analyzer::semantic::DeclarationSegmentKind,
) -> &'static str {
    use brokk_bifrost::analyzer::semantic::DeclarationSegmentKind::*;
    match kind {
        File => "file",
        Namespace => "namespace",
        Type => "type",
        Function => "function",
        Method => "method",
        Constructor => "constructor",
        Initializer => "initializer",
        LocalFunction => "local_function",
        Lambda => "lambda",
        Closure => "closure",
        AnonymousCallable => "anonymous_callable",
    }
}

fn format_anchor(anchor: SourceAnchor) -> String {
    format!("{}#{}", format_span(anchor.span()), anchor.occurrence())
}

fn format_span(span: SourceSpan) -> String {
    let start = span.start();
    let end = span.end();
    format!(
        "L{}:{}-L{}:{}",
        start.line() + 1,
        start.byte_column() + 1,
        end.line() + 1,
        end.byte_column() + 1
    )
}

fn span_width(span: SourceSpan) -> u32 {
    span.end_byte() - span.start_byte()
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let head = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{head}...")
    } else {
        head
    }
}

fn normalize_topology(value: &str) -> String {
    value
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_owned()
}
