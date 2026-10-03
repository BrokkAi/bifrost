//! Exact source statement entries from one immutable procedure artifact.
//!
//! A query must enumerate executable syntax from a prepared tree before asking
//! for an entry. A missing producer site for such syntax is open coverage, not
//! evidence that the statement is unreachable.

use crate::analyzer::languages::ProcedureSyntaxRoles;
use crate::analyzer::languages::language_support;
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, Reachability, forward_reachability,
};
use crate::analyzer::semantic::type_flow::{
    source_span_for_node, validate_prepared_syntax_source_for_procedure,
};
use crate::analyzer::semantic::{
    ContentIdentity, EvidenceCompleteness, OverlaySnapshotId, ProcedureHandle, ProcedureSemantics,
    ProgramPointId, ProofStatus, SemanticCapability, SemanticGapDischarge, SemanticGapSubject,
    SourceMappingKind, SourceRevision, SourceSpan, StableDigest, WorkspaceMountId,
    WorkspaceRelativePath,
};
use crate::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
use crate::analyzer::tree_sitter_analyzer::{PreparedSourceOrigin, PreparedSyntaxTree};
use crate::analyzer::{ProjectFile, Range, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use crate::text_utils::{compute_line_starts, line_column_for_offset};
use brokk_bifrost_core::analyzer::tree_walk::node_range;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementEntryOpen {
    SourceSnapshotMismatch,
    MissingProducerSite,
}

/// An exact span-to-entry index for one procedure and one prepared source.
///
/// Several points may enter the same statement (for example, distinct finally
/// routes), so callers must inspect every returned point. An entry point may
/// also be shared with an enclosing statement; the producer's source mapping
/// identifies which statement each row describes.
pub struct StatementEntryIndex {
    by_span: HashMap<SourceSpan, Vec<ProgramPointId>>,
}

impl StatementEntryIndex {
    pub fn new(
        procedure: &ProcedureHandle,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
    ) -> Result<Self, StatementEntryOpen> {
        let key = procedure.artifact().key();
        let path = WorkspaceRelativePath::try_from_path(file.rel_path())
            .map_err(|_| StatementEntryOpen::SourceSnapshotMismatch)?;
        let content =
            ContentIdentity::from_digest(StableDigest::from_array(prepared.source_sha256()));
        let revision_matches = match (key.revision(), prepared.origin()) {
            (SourceRevision::Disk { content: expected }, PreparedSourceOrigin::Disk) => {
                content == expected
            }
            (
                SourceRevision::Overlay {
                    content: expected,
                    snapshot,
                },
                PreparedSourceOrigin::Overlay,
            ) => {
                content == expected
                    && prepared.overlay_revision().is_some_and(|overlay| {
                        OverlaySnapshotId::hash_bytes(overlay.get().to_le_bytes()) == snapshot
                    })
            }
            _ => false,
        };
        if key.mount() != WorkspaceMountId::from_root(file.root())
            || key.path() != &path
            || key.language() != prepared.dialect()
            || !revision_matches
        {
            return Err(StatementEntryOpen::SourceSnapshotMismatch);
        }

        let semantics = procedure.semantics();
        let mut by_span = HashMap::default();
        for site in semantics.statement_entries() {
            let source = semantics
                .source_mapping(site.source)
                .expect("validated statement entry has an exact source mapping");
            by_span
                .entry(source.locator.anchor().span())
                .or_insert_with(Vec::new)
                .push(site.point);
        }
        Ok(Self { by_span })
    }

    /// Look up one independently enumerated executable statement node.
    ///
    /// The caller is responsible for proving that only one candidate syntax
    /// node of the relevant statement role owns this exact span. A missing
    /// site is explicitly open; it must not be treated as a dead statement.
    pub fn at_span(&self, span: SourceSpan) -> Result<&[ProgramPointId], StatementEntryOpen> {
        self.by_span
            .get(&span)
            .map(Vec::as_slice)
            .ok_or(StatementEntryOpen::MissingProducerSite)
    }
}

const MAX_STATEMENT_SOURCE_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementVerdict {
    Reachable,
    Unreachable,
    Open(&'static str),
}

#[derive(Debug, Clone, Copy)]
pub struct StatementCoordinates {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone)]
pub struct StatementAssessment {
    pub range: Range,
    pub coordinates: StatementCoordinates,
    pub kind: &'static str,
    pub verdict: StatementVerdict,
}

#[derive(Debug, Clone)]
pub struct StatementAssessments {
    pub rows: Vec<StatementAssessment>,
    pub complete: bool,
    pub reason: Option<&'static str>,
}

fn unavailable(reason: &'static str) -> StatementAssessments {
    StatementAssessments {
        rows: Vec::new(),
        complete: false,
        reason: Some(reason),
    }
}

fn algorithm_open_reason(error: CfgAlgorithmError<ProgramPointId>) -> &'static str {
    match error {
        CfgAlgorithmError::Cancelled { .. } => "cancelled",
        CfgAlgorithmError::ExceededBudget(_) => "control_budget_exhausted",
        CfgAlgorithmError::InvalidNode(point) => {
            panic!("validated procedure has an invalid CFG point {point:?}")
        }
    }
}

fn scan_control_evidence(
    semantics: &ProcedureSemantics,
    reachable: &Reachability<ProgramPointId>,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<Option<&'static str>, CfgAlgorithmError<ProgramPointId>> {
    let complete_evidence = |id| {
        let evidence = semantics
            .evidence_row(id)
            .expect("validated control row has evidence");
        evidence.proof == ProofStatus::Proven
            && evidence.completeness == EvidenceCompleteness::Complete
    };
    for gap in semantics.gaps() {
        request.visit_node::<ProgramPointId>()?;
        // Reachability depends only on the retained successor topology. A
        // retained-topology gap keeps every successor, and a non-rejoining
        // exceptional exit omits only a route that enters no handler or
        // cleanup code and never resumes this procedure, so neither can make
        // a statement reachable.
        if matches!(
            gap.discharge,
            SemanticGapDischarge::RetainedControlTopology
                | SemanticGapDischarge::NonRejoiningExceptionalExit
        ) {
            continue;
        }
        if matches!(
            gap.capability,
            SemanticCapability::NormalControlFlow
                | SemanticCapability::ExceptionalControlFlow
                | SemanticCapability::CleanupControlFlow
                | SemanticCapability::NonLocalControl
                | SemanticCapability::GuardFacts
                | SemanticCapability::SwitchFacts
        ) && (gap.subject == SemanticGapSubject::Procedure
            || reachable.contains(semantics, gap.point))
        {
            return Ok(Some("control_evidence_incomplete"));
        }
    }
    for point in semantics.points() {
        request.visit_node::<ProgramPointId>()?;
        if !reachable.contains(semantics, point.id) {
            continue;
        }
        if !complete_evidence(point.evidence) {
            return Ok(Some("control_evidence_incomplete"));
        }
        if point.id != semantics.normal_exit_point()
            && point.id != semantics.exceptional_exit_point()
            && semantics.successor_edges(point.id).len() == 0
        {
            return Ok(Some("control_frontier_incomplete"));
        }
    }
    for edge in semantics.control_edges() {
        request.visit_edge::<ProgramPointId>()?;
        if reachable.contains(semantics, edge.source_point) && !complete_evidence(edge.evidence) {
            return Ok(Some("control_evidence_incomplete"));
        }
    }
    Ok(None)
}

/// Prepared syntax validated against one procedure's artifact snapshot, with
/// the syntax roles of the procedure's language.
pub(crate) struct ProcedureSyntax {
    pub(crate) file: ProjectFile,
    pub(crate) syntax: std::sync::Arc<PreparedSyntaxTree>,
    pub(crate) roles: ProcedureSyntaxRoles,
}

impl ProcedureSyntax {
    /// Load and validate the prepared tree for `procedure`. The error is a
    /// stable open reason for the caller's row or diagnostic.
    pub(crate) fn prepare(
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, &'static str> {
        let language = procedure.artifact().key().language().language();
        let roles = language_support(language)
            .and_then(|support| support.procedure_syntax_roles())
            .ok_or("unsupported_language")?;
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err("cancelled");
        }
        let file = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            procedure.artifact().key().path().as_path(),
        );
        let syntax = workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == language)
            .map(|provider| {
                provider.structural_syntax_limited(&file, MAX_STATEMENT_SOURCE_BYTES, cancellation)
            });
        let syntax = match syntax {
            Some(StructuralSyntaxLimitedOutcome::Available(syntax)) => syntax,
            Some(StructuralSyntaxLimitedOutcome::Exceeded { .. }) => {
                return Err("source_budget_exhausted");
            }
            Some(StructuralSyntaxLimitedOutcome::Cancelled) => return Err("cancelled"),
            Some(StructuralSyntaxLimitedOutcome::Unavailable) | None => {
                return Err("prepared_syntax_unavailable");
            }
        };
        let syntax = validate_prepared_syntax_source_for_procedure(
            workspace,
            procedure,
            &file,
            syntax.into_inner(),
        )
        .map_err(|_| "source_identity_mismatch")?;
        Ok(Self {
            file,
            syntax,
            roles,
        })
    }

    /// The unique syntax node that owns `procedure`: its exact source span
    /// and a node role that matches the procedure kind. Wrappers can share a
    /// callable's span, so the role match must select exactly one node.
    pub(crate) fn procedure_node(
        &self,
        procedure: &ProcedureHandle,
    ) -> Result<Node<'_>, &'static str> {
        let semantics = procedure.semantics();
        let mapping = semantics
            .source_mapping(semantics.source())
            .expect("validated procedure source exists");
        if mapping.kind != SourceMappingKind::Exact {
            return Err("procedure_mapping_inexact");
        }
        let span = mapping.locator.anchor().span();
        let mut node = self
            .syntax
            .tree()
            .root_node()
            .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
            .ok_or("procedure_syntax_missing")?;
        let mut matching_roles = 0;
        let mut selected = None;
        loop {
            if source_span_for_node(node) != span {
                break;
            }
            if (self.roles.procedure_matches)(semantics.kind(), node) {
                matching_roles += 1;
                selected = Some(node);
            }
            let Some(parent) = node.parent() else {
                break;
            };
            node = parent;
        }
        let node = selected
            .filter(|_| matching_roles == 1)
            .ok_or("procedure_syntax_ambiguous")?;
        if node.has_error() {
            return Err("procedure_syntax_recovery");
        }
        Ok(node)
    }
}

/// Assess every executable statement owned by one exact semantic procedure.
/// A missing site or incomplete control proof is an open row.
pub fn statement_assessments(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> StatementAssessments {
    let prepared = match ProcedureSyntax::prepare(workspace, procedure, cancellation) {
        Ok(prepared) => prepared,
        Err(reason) => return unavailable(reason),
    };
    let ProcedureSyntax {
        file,
        syntax,
        roles: grammar,
    } = &prepared;
    let Ok(index) = StatementEntryIndex::new(procedure, file, syntax) else {
        return unavailable("source_identity_mismatch");
    };
    let semantics = procedure.semantics();
    let procedure_node = match prepared.procedure_node(procedure) {
        Ok(node) => node,
        Err(reason) => return unavailable(reason),
    };
    // The procedure's own body block is its entry, not a statement of it.
    let procedure_body = procedure_node
        .child_by_field_name("body")
        .unwrap_or(procedure_node);

    let line_starts = compute_line_starts(syntax.source());
    let mut stack = vec![procedure_node];
    let mut candidates = Vec::new();
    let mut span_counts = HashMap::<SourceSpan, usize>::default();
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
        if node.id() != procedure_node.id() && (grammar.nested_procedure)(node) {
            continue;
        }
        if node.id() != procedure_body.id()
            && let Some(kind) = (grammar.statement_kind)(node)
        {
            let span = source_span_for_node(node);
            *span_counts.entry(span).or_default() += 1;
            let (start_line, start_column) =
                line_column_for_offset(syntax.source(), &line_starts, node.start_byte());
            let (end_line, end_column) =
                line_column_for_offset(syntax.source(), &line_starts, node.end_byte());
            candidates.push((
                span,
                node.has_error(),
                StatementAssessment {
                    range: node_range(node),
                    coordinates: StatementCoordinates {
                        start_line,
                        start_column,
                        end_line,
                        end_column,
                    },
                    kind,
                    verdict: StatementVerdict::Open("syntax_recovery"),
                },
            ));
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }

    let uncancelled = CancellationToken::new();
    let mut budget = CfgAlgorithmBudget::default();
    let mut request = CfgAlgorithmRequest::new(&mut budget, cancellation.unwrap_or(&uncancelled));
    let reachable = forward_reachability(semantics, semantics.entry_point(), &mut request);
    let control_open = match &reachable {
        Err(error) => Some(algorithm_open_reason(*error)),
        Ok(reachable) => match scan_control_evidence(semantics, reachable, &mut request) {
            Ok(reason) => reason,
            Err(error) => Some(algorithm_open_reason(error)),
        },
    };
    let mut rows = Vec::with_capacity(candidates.len());
    for (span, malformed, mut row) in candidates {
        if let Err(error) = request.visit_node::<ProgramPointId>() {
            return unavailable(algorithm_open_reason(error));
        }
        if !malformed {
            row.verdict = if span_counts[&span] != 1 {
                StatementVerdict::Open("ambiguous_statement_span")
            } else if let Some(reason) = control_open {
                StatementVerdict::Open(reason)
            } else {
                match index.at_span(span) {
                    Err(StatementEntryOpen::MissingProducerSite) => {
                        StatementVerdict::Open("missing_statement_entry")
                    }
                    Err(StatementEntryOpen::SourceSnapshotMismatch) => {
                        StatementVerdict::Open("source_identity_mismatch")
                    }
                    Ok(entries) => {
                        let reachable = reachable.as_ref().expect("complete control proof");
                        if entries
                            .iter()
                            .any(|point| reachable.contains(semantics, *point))
                        {
                            StatementVerdict::Reachable
                        } else {
                            StatementVerdict::Unreachable
                        }
                    }
                }
            };
        }
        rows.push(row);
    }
    rows.sort_unstable_by_key(|row| (row.range.start_byte, row.range.end_byte));
    StatementAssessments {
        rows,
        complete: true,
        reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        CancellationToken, ProcedureKind, SemanticBudget, SemanticRequest, source_anchor,
    };
    use crate::analyzer::tree_sitter_analyzer::{
        PreparedSourceOrigin, PreparedSyntaxSource, WalkControl, walk_named_tree_preorder,
    };
    use crate::analyzer::{AnalyzerConfig, Language, LanguageDialect};
    use crate::inline_project::InlineTestProject;
    use std::sync::Arc;

    fn parse_prepared(source: &str) -> PreparedSyntaxTree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("Java grammar loads");
        PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::from(source)),
            parser.parse(source, None).expect("Java source parses"),
            crate::text_utils::compute_line_starts(source),
            LanguageDialect::Standard(Language::Java),
            PreparedSourceOrigin::Disk,
            None,
        )
    }

    fn statement_span(prepared: &PreparedSyntaxTree, text: &str) -> SourceSpan {
        let mut found = None;
        walk_named_tree_preorder(prepared.tree().root_node(), true, |node| {
            if prepared.source().get(node.byte_range()) == Some(text) {
                found = Some(source_anchor(node, 0).expect("valid statement span").span());
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        });
        found.unwrap_or_else(|| panic!("missing statement {text}"))
    }

    #[test]
    fn java_statement_entries_retain_dead_and_specialized_cleanup_routes() {
        let source = r#"class App {
  void dead() { return; removed(); }
  void cleanup(boolean flag) {
    try { if (flag) return; throw new RuntimeException(); }
    finally { done(); }
  }
  void cycle() { do { tick(); } while (false); }
  void open(boolean flag) { synchronized(this) { if (flag) return; } return; missed(); }
  void outer() { Runnable r = () -> { inner(); }; return; after(); }
  int switchReturn(int n) { return switch (n) { default -> 1; }; }
  int switchInitializer(int m) { int x = switch (m) { default -> 2; }; return x; }
  void switchStatement(int q) { switch (q) { default: return; } }
  void forInitializer() { for (int i = 0; i < 1; i++) { break; } }
}"#;
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/App.java", source)
            .build();
        let file = project.file("src/App.java");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Java semantics materialize")
            .available_value()
            .cloned()
            .expect("Java artifact available");
        let prepared = parse_prepared(source);
        let method = |name| {
            artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .unwrap_or_else(|| panic!("method {name} exists"))
        };

        let dead = StatementEntryIndex::new(&method("dead"), &file, &prepared)
            .expect("same Java snapshot");
        assert_eq!(
            dead.at_span(statement_span(&prepared, "removed();"))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            dead.at_span(statement_span(
                &prepared,
                "void dead() { return; removed(); }"
            )),
            Err(StatementEntryOpen::MissingProducerSite)
        );
        let assessed = statement_assessments(&analyzer, &method("dead"), None);
        assert!(assessed.complete, "{:?}", assessed.reason);
        let removed = statement_span(&prepared, "removed();");
        assert!(assessed.rows.iter().any(|row| {
            row.range.start_byte == removed.start_byte() as usize
                && row.range.end_byte == removed.end_byte() as usize
                && row.verdict == StatementVerdict::Unreachable
        }));
        let returned = statement_span(&prepared, "return;");
        assert!(assessed.rows.iter().any(|row| {
            row.range.start_byte == returned.start_byte() as usize
                && row.range.end_byte == returned.end_byte() as usize
                && row.verdict == StatementVerdict::Reachable
        }));

        let open = statement_assessments(&analyzer, &method("open"), None);
        let missed = statement_span(&prepared, "missed();");
        assert!(open.rows.iter().any(|row| {
            row.range.start_byte == missed.start_byte() as usize
                && row.range.end_byte == missed.end_byte() as usize
                && row.verdict == StatementVerdict::Open("control_evidence_incomplete")
        }));

        let outer = statement_assessments(&analyzer, &method("outer"), None);
        assert!(outer.complete, "{:?}", outer.reason);
        let inner = statement_span(&prepared, "inner();");
        assert!(outer.rows.iter().all(|row| {
            row.range.start_byte != inner.start_byte() as usize
                || row.range.end_byte != inner.end_byte() as usize
        }));

        for (name, text) in [
            ("switchReturn", "switch (n) { default -> 1; }"),
            ("switchInitializer", "switch (m) { default -> 2; }"),
        ] {
            let assessed = statement_assessments(&analyzer, &method(name), None);
            assert!(assessed.complete, "{name}: {:?}", assessed.reason);
            assert!(
                assessed
                    .rows
                    .iter()
                    .all(|row| !matches!(row.verdict, StatementVerdict::Open(_))),
                "{name}: {:?}",
                assessed.rows
            );
            let expression = statement_span(&prepared, text);
            assert!(assessed.rows.iter().all(|row| {
                row.range.start_byte != expression.start_byte() as usize
                    || row.range.end_byte != expression.end_byte() as usize
            }));
        }
        let standalone = statement_assessments(&analyzer, &method("switchStatement"), None);
        assert!(standalone.complete, "{:?}", standalone.reason);
        assert!(standalone.rows.iter().any(|row| row.kind == "switch"));

        let for_initializer = statement_assessments(&analyzer, &method("forInitializer"), None);
        assert!(for_initializer.complete, "{:?}", for_initializer.reason);
        let mut initializer = None;
        walk_named_tree_preorder(prepared.tree().root_node(), true, |node| {
            if node.kind() == "local_variable_declaration"
                && node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "for_statement")
            {
                initializer = Some(source_span_for_node(node));
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        });
        let initializer = initializer.expect("for initializer syntax exists");
        assert!(for_initializer.rows.iter().all(|row| {
            row.range.start_byte != initializer.start_byte() as usize
                || row.range.end_byte != initializer.end_byte() as usize
        }));

        let cleanup = StatementEntryIndex::new(&method("cleanup"), &file, &prepared)
            .expect("same Java snapshot");
        assert!(
            cleanup
                .at_span(statement_span(&prepared, "done();"))
                .unwrap()
                .len()
                > 1,
            "finally must retain every specialized entry"
        );

        let cycle = StatementEntryIndex::new(&method("cycle"), &file, &prepared)
            .expect("same Java snapshot");
        assert_eq!(
            cycle
                .at_span(statement_span(&prepared, "do { tick(); } while (false);"))
                .unwrap(),
            cycle
                .at_span(statement_span(&prepared, "{ tick(); }"))
                .unwrap(),
            "the body can share its enclosing do point without losing its own source identity"
        );

        let changed = parse_prepared(&format!("{source}\n// changed"));
        assert!(matches!(
            StatementEntryIndex::new(&method("dead"), &file, &changed),
            Err(StatementEntryOpen::SourceSnapshotMismatch)
        ));
    }

    #[test]
    fn java_statement_entries_exclude_the_procedure_body_but_retain_nested_blocks() {
        let source = r#"class Sample {
  Sample() {}
  void nested(boolean flag) { if (flag) {} }
}"#;
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/Sample.java", source)
            .build();
        let file = project.file("src/Sample.java");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Java semantics materialize")
            .available_value()
            .cloned()
            .expect("Java artifact available");
        let procedure = |kind, name| {
            artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure.kind() == kind
                        && procedure
                            .locator()
                            .declaration()
                            .segments()
                            .last()
                            .and_then(|segment| segment.name())
                            == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .unwrap_or_else(|| panic!("{kind:?} {name} exists"))
        };

        let constructor = statement_assessments(
            &analyzer,
            &procedure(ProcedureKind::Constructor, "Sample"),
            None,
        );
        assert!(constructor.complete, "{:?}", constructor.reason);
        assert!(constructor.rows.is_empty(), "{:?}", constructor.rows);

        let nested =
            statement_assessments(&analyzer, &procedure(ProcedureKind::Method, "nested"), None);
        assert!(nested.complete, "{:?}", nested.reason);
        let blocks = nested
            .rows
            .iter()
            .filter(|row| row.kind == "block")
            .collect::<Vec<_>>();
        assert_eq!(blocks.len(), 1, "{:?}", nested.rows);
        assert_eq!(blocks[0].verdict, StatementVerdict::Reachable);
    }
}
