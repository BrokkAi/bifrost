//! Selecting a semantic program point from a source position.
//!
//! One owner for the source mapping from a structural AST node to a program
//! point. RQL's `program-point-of` and the flow and reachability tools both
//! call [`source_mapped_points`]. A position that does not select exactly one
//! point is a typed refusal, never the nearest point.

use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
use brokk_bifrost_analysis::analyzer::semantic::{
    ProcedureSemantics, ProgramPointHandle, ProgramPointId, SemanticBudget, SemanticEffect,
    SemanticOutcome, SemanticRequest, StructuralNodeIdentity,
};
use brokk_bifrost_analysis::analyzer::structural::facts::{FileFacts, NormalizedNode};
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::text_utils::compute_line_starts;

use crate::site_context::{
    KnownValue, NotAnalyzedCause, SiteContext, SiteLocation, SiteRole, SiteValue, UnknownValueCause,
};

/// Operation labels passed to the `charge` callback of [`source_mapped_points`].
pub const POINT_OPERATION: &str = "program-point selection";
pub const SUSPEND_OPERATION: &str = "program-point suspend selection";

/// The program points of one procedure whose exact source mapping names
/// `identity`.
///
/// An await node selects only a point that carries an `AsyncSuspend` event:
/// uniqueness depends on the complete point inventory, even when one point has
/// an exact structural mapping. `charge` is called once per examined point and
/// once per examined event; when it returns false the scan stops and the
/// result is `None`, so the caller reports its own budget or cancellation.
pub fn source_mapped_points(
    semantics: &ProcedureSemantics,
    identity: StructuralNodeIdentity,
    is_await: bool,
    charge: &mut dyn FnMut(&'static str) -> bool,
) -> Option<Vec<ProgramPointId>> {
    let mut points = Vec::new();
    for point in semantics.points() {
        if !charge(POINT_OPERATION) {
            return None;
        }
        let point_matches = semantics
            .source_mapping(point.source)
            .is_some_and(|mapping| mapping.ast_identity == Some(identity));
        if !point_matches {
            continue;
        }
        if is_await {
            let mut suspend_matches = false;
            for event in &point.events {
                if !charge(SUSPEND_OPERATION) {
                    return None;
                }
                if matches!(event.effect, SemanticEffect::AsyncSuspend { .. }) {
                    suspend_matches = true;
                    break;
                }
            }
            if !suspend_matches {
                continue;
            }
        }
        points.push(point.id);
    }
    Some(points)
}

/// A position in a source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcePosition {
    /// 1-based line and 1-based column counting characters.
    LineColumn { line: usize, column: usize },
    /// Byte offset into the file's source.
    ByteOffset(usize),
}

/// The point a position selected, with the site it names.
#[derive(Debug, Clone)]
pub struct SelectedProgramPoint {
    pub point: ProgramPointHandle,
    pub site: SiteContext,
}

/// Why a position did not select exactly one program point.
#[derive(Debug, Clone)]
pub enum PointSelectionRefusal {
    /// No structural node of an admissible kind contains the position, or the
    /// position lies outside the file.
    NoNodeAtPosition,
    /// The innermost admissible nodes map to more than one program point.
    Ambiguous(Vec<ProgramPointHandle>),
    /// The selected node has no program point (its kind is not lowered).
    UnsupportedNode(NormalizedKind),
    /// The file has no structural facts in this workspace.
    FileNotAnalyzed,
    /// The semantic artifact for the file is not available.
    ProcedureUnavailable(NotAnalyzedCause),
}

/// Select the program point at `position` in `file`.
///
/// The node comes from the structural facts, which are derived from the
/// tree-sitter AST. Of the nodes whose span contains the position and whose
/// kind suits `role`, only those with the smallest span are candidates; the
/// source mapping then selects among them.
pub fn select_program_point(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    position: SourcePosition,
    role: SiteRole,
    cancellation: &CancellationToken,
) -> Result<SelectedProgramPoint, PointSelectionRefusal> {
    let language = brokk_bifrost_core::analyzer::common::language_for_file(file);
    let facts = workspace
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .and_then(|provider| provider.structural_facts(file))
        .ok_or(PointSelectionRefusal::FileNotAnalyzed)?;

    let offset = match position {
        SourcePosition::ByteOffset(offset) => offset,
        SourcePosition::LineColumn { line, column } => {
            let starts = compute_line_starts(facts.source());
            let line_start = line
                .checked_sub(1)
                .and_then(|index| starts.get(index))
                .copied()
                .ok_or(PointSelectionRefusal::NoNodeAtPosition)?;
            let line_end = starts.get(line).copied().unwrap_or(facts.source().len());
            let text = &facts.source()[line_start..line_end];
            let skipped = column
                .checked_sub(1)
                .ok_or(PointSelectionRefusal::NoNodeAtPosition)?;
            let (byte, _) = text
                .char_indices()
                .chain(std::iter::once((text.len(), '\n')))
                .nth(skipped)
                .ok_or(PointSelectionRefusal::NoNodeAtPosition)?;
            line_start + byte
        }
    };

    let mut smallest = usize::MAX;
    let mut candidates: Vec<u32> = Vec::new();
    for (id, node) in facts.nodes().iter().enumerate() {
        let span = node.span();
        if !(span.start_byte <= offset && offset < span.end_byte) || !role_admits(&role, node.kind)
        {
            continue;
        }
        let length = span.end_byte - span.start_byte;
        if length < smallest {
            smallest = length;
            candidates.clear();
        }
        if length == smallest {
            candidates.push(id as u32);
        }
    }
    let Some(&first) = candidates.first() else {
        return Err(PointSelectionRefusal::NoNodeAtPosition);
    };

    let mut budget = SemanticBudget::default();
    let outcome = workspace
        .materialize_program_semantics(file, &mut SemanticRequest::new(&mut budget, cancellation))
        .map_err(|error| {
            PointSelectionRefusal::ProcedureUnavailable(NotAnalyzedCause::ProviderFailed(error))
        })?;
    let artifact = match outcome {
        SemanticOutcome::Complete { value, .. } => value,
        SemanticOutcome::Unsupported { capability, .. } => {
            return Err(PointSelectionRefusal::ProcedureUnavailable(
                NotAnalyzedCause::Unsupported(capability),
            ));
        }
        SemanticOutcome::ExceededBudget { exceeded, .. } => {
            return Err(PointSelectionRefusal::ProcedureUnavailable(
                NotAnalyzedCause::ExceededBudget(exceeded),
            ));
        }
        SemanticOutcome::Cancelled { .. } => {
            return Err(PointSelectionRefusal::ProcedureUnavailable(
                NotAnalyzedCause::Cancelled,
            ));
        }
        SemanticOutcome::Ambiguous { .. }
        | SemanticOutcome::Unknown { .. }
        | SemanticOutcome::Unproven { .. } => {
            return Err(PointSelectionRefusal::ProcedureUnavailable(
                NotAnalyzedCause::Unknown,
            ));
        }
    };

    let mut mapped: Vec<(u32, ProgramPointHandle)> = Vec::new();
    for &node_id in &candidates {
        let identity = StructuralNodeIdentity::new(facts.source_identity(), node_id);
        let is_await = facts.node(node_id).kind == NormalizedKind::Await;
        for semantics in artifact.procedures().iter() {
            let ids = source_mapped_points(semantics, identity, is_await, &mut |_| {
                !cancellation.is_cancelled()
            })
            .ok_or(PointSelectionRefusal::ProcedureUnavailable(
                NotAnalyzedCause::Cancelled,
            ))?;
            let procedure = artifact
                .procedure_handle(semantics.id())
                .expect("an artifact owns its procedures");
            for id in ids {
                mapped.push((
                    node_id,
                    procedure
                        .point_handle(id)
                        .expect("a procedure owns its points"),
                ));
            }
        }
    }

    match mapped.as_slice() {
        [] => Err(PointSelectionRefusal::UnsupportedNode(
            facts.node(first).kind,
        )),
        [(node_id, point)] => {
            let node = facts.node(*node_id);
            let span = node.span();
            Ok(SelectedProgramPoint {
                point: point.clone(),
                site: SiteContext {
                    site: source_site(file, &facts, span.start_byte..span.end_byte),
                    role,
                    value: node_site_value(node),
                },
            })
        }
        _ => Err(PointSelectionRefusal::Ambiguous(
            mapped.into_iter().map(|(_, point)| point).collect(),
        )),
    }
}

/// The source location of a byte range of `file`, as `facts` read it.
pub fn source_site(
    file: &ProjectFile,
    facts: &FileFacts,
    byte_range: std::ops::Range<usize>,
) -> SiteLocation {
    let (start_line, start_column) = facts.line_column_of_byte(byte_range.start);
    let (end_line, end_column) = facts.line_column_of_byte(byte_range.end);
    SiteLocation::Source {
        path: file.clone(),
        text: facts.source()[byte_range.clone()].to_string(),
        byte_range,
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

/// Borrow a structural constant without copying its retained payload.
pub fn node_site_value_ref(node: &NormalizedNode) -> crate::site_context::SiteValueRef<'_> {
    use crate::site_context::{SiteValueRef, UnknownValueCauseRef};
    match (&node.string_value, &node.integer_literal_value) {
        (Some(text), _) => SiteValueRef::Str(text),
        (None, Some(integer)) => match &integer.decimal {
            Some(decimal) => SiteValueRef::Int {
                decimal,
                negative: integer.negative,
            },
            None => SiteValueRef::Unknown(UnknownValueCauseRef::ConstantPayloadUnavailable),
        },
        (None, None) => SiteValueRef::Unknown(UnknownValueCauseRef::NotConstant),
    }
}

/// What the structural facts of `node` say about its constant value.
pub fn node_site_value(node: &NormalizedNode) -> SiteValue {
    match (&node.string_value, &node.integer_literal_value) {
        (Some(text), _) => SiteValue::Known(KnownValue::Str(text.clone())),
        (None, Some(integer)) => match &integer.decimal {
            Some(decimal) => SiteValue::Known(KnownValue::Int(if integer.negative {
                format!("-{decimal}")
            } else {
                decimal.clone()
            })),
            None => SiteValue::Unknown(UnknownValueCause::ConstantPayloadUnavailable),
        },
        (None, None) => SiteValue::Unknown(UnknownValueCause::NotConstant),
    }
}

/// Whether a node of `kind` can be selected for `role`. Roles without a
/// dedicated node kind select the innermost node at the position.
fn role_admits(role: &SiteRole, kind: NormalizedKind) -> bool {
    match role {
        SiteRole::Call => kind == NormalizedKind::Call,
        SiteRole::Return => kind == NormalizedKind::Return,
        SiteRole::FieldWrite { .. } | SiteRole::FieldRead { .. } => {
            kind == NormalizedKind::FieldAccess
        }
        SiteRole::Statement => kind.is_statement_level(),
        SiteRole::Value | SiteRole::Binding | SiteRole::Argument { .. } | SiteRole::Receiver => {
            true
        }
    }
}
