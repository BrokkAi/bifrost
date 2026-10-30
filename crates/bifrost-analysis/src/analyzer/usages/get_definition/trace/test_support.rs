use super::*;

use crate::analyzer::semantic_model::SemanticModelActivationEvidence;
use crate::analyzer::structural::occurrences::OccurrenceRole;
use crate::analyzer::usages::get_definition::DefinitionLookupRequest;
use crate::analyzer::{AnalyzerConfig, Language, WorkspaceAnalyzer};
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use std::path::Path;

#[doc(hidden)]
pub struct BoundaryFixture {
    pub(super) _project: BuiltInlineTestProject,
    #[doc(hidden)]
    pub workspace: WorkspaceAnalyzer,
    #[doc(hidden)]
    pub file: ProjectFile,
    #[doc(hidden)]
    pub source: String,
}

impl BoundaryFixture {
    #[doc(hidden)]
    pub fn new(language: Language, relative_path: &str, source: &str) -> Self {
        Self::with_config(language, relative_path, source, |_| {
            AnalyzerConfig::default()
        })
    }

    /// A fixture whose analyzer config is built from the canonical project
    /// root, for boundary tests that point external-dependency config at
    /// artifacts written inside the fixture.
    #[doc(hidden)]
    pub fn with_config(
        language: Language,
        relative_path: &str,
        source: &str,
        config: impl FnOnce(&Path) -> AnalyzerConfig,
    ) -> Self {
        let project = InlineTestProject::with_language(language)
            .file(relative_path, source)
            .build();
        let config = config(project.root());
        let file = project.file(relative_path);
        let workspace = project.workspace_analyzer(config);
        Self {
            _project: project,
            workspace,
            file,
            source: source.to_owned(),
        }
    }

    /// The traced resolution of the reference whose first token starts
    /// `needle`.
    #[doc(hidden)]
    pub fn trace(&self, needle: &str) -> (DefinitionLookupOutcome, ResolutionTraceResult) {
        let requests = vec![self.request_for(needle)];
        resolve_definition_batch_with_trace(
            self.workspace.analyzer(),
            requests,
            self.file.clone(),
            Arc::from(self.source.as_str()),
            &CancellationToken::new(),
        )
        .pop()
        .expect("one traced outcome per request")
    }

    #[doc(hidden)]
    pub fn request_for(&self, needle: &str) -> DefinitionLookupRequest {
        let start = self
            .source
            .find(needle)
            .unwrap_or_else(|| panic!("fixture does not contain {needle:?}"));
        DefinitionLookupRequest {
            file: self.file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: None,
        }
    }

    /// The same traced resolution as [`Self::trace`], reached through the
    /// public probe entry point (#1885).
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn trace_via_probe_entry_point(
        &self,
        needle: &str,
    ) -> (DefinitionLookupOutcome, ResolutionTraceResult) {
        let requests = vec![self.request_for(needle)];
        super::super::resolve_definition_batch_with_source_traced(
            self.workspace.analyzer(),
            requests,
            self.file.clone(),
            Arc::from(self.source.as_str()),
        )
        .pop()
        .expect("one traced outcome per request")
    }
}

/// The external-route rows of one trace: `(boundary, external_target)`.
/// Empty means the resolver never drew a boundary, which fails the test
/// asking about one.
#[doc(hidden)]
pub fn external_routes(trace: &ResolutionTraceResult) -> Vec<(BoundaryStatus, Option<String>)> {
    let routes: Vec<_> = route_rows(trace);
    assert!(
        !routes.is_empty(),
        "a boundary outcome always reports the route it took: {:?}",
        trace.candidates
    );
    routes
}

#[doc(hidden)]
pub fn route_rows(trace: &ResolutionTraceResult) -> Vec<(BoundaryStatus, Option<String>)> {
    crate::test_support::external_route_candidates(trace)
        .into_iter()
        .map(|row| (row.boundary, row.external_target.clone()))
        .collect()
}

#[doc(hidden)]
pub fn assert_declared_unindexed_routes(routes: &[(BoundaryStatus, Option<String>)]) {
    assert!(
        routes
            .iter()
            .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalDeclaredUnindexed),
        "a declared but unread dependency stays accountable: {routes:?}"
    );
}

/// The written names of one trace's external-route rows, in order.
#[doc(hidden)]
pub fn route_names(trace: &ResolutionTraceResult) -> Vec<String> {
    crate::test_support::external_route_candidates(trace)
        .into_iter()
        .filter_map(|row| match &row.candidate {
            TraceCandidateRef::ExternalRoute { name } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

/// Whether the traced occurrence row at the reference starting with
/// `needle` carries the route row the definition trace published.
///
/// This is the exact join `candidates_of` performs: it re-locates a
/// reference occurrence in the traced file by AST identity and reads the
/// candidate rows hanging off it. Both consumers reading one publication
/// means this row exists and carries the route (#3466).
#[doc(hidden)]
pub fn assert_boundary_route_joins_occurrence(
    fixture: &BoundaryFixture,
    needle: &str,
    role: OccurrenceRole,
) {
    use crate::analyzer::structural::occurrence_rows::{
        OccurrenceDerivationOptions, occurrences_for_file_with_options,
    };

    let start = fixture
        .source
        .find(needle)
        .unwrap_or_else(|| panic!("fixture does not contain {needle:?}"));
    let result = occurrences_for_file_with_options(
        fixture.workspace.analyzer(),
        &fixture.file,
        OccurrenceDerivationOptions::WITH_CANDIDATES,
        &CancellationToken::new(),
    )
    .expect("occurrence rows");
    let row = result
        .rows
        .iter()
        .find(|row| row.range.start_byte == start)
        .unwrap_or_else(|| {
            panic!(
                "no occurrence row starts at byte {start} ({needle:?}): {:#?}",
                result
                    .rows
                    .iter()
                    .map(|row| (&row.raw_spelling, row.role))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        row.role, role,
        "the reference token `{needle}` is the row candidates_of joins on"
    );
    let candidates = row
        .candidates
        .as_ref()
        .unwrap_or_else(|| panic!("no candidates derived for `{needle}`"));
    let routes = candidates
        .candidates
        .iter()
        .filter(|candidate| matches!(candidate.candidate, TraceCandidateRef::ExternalRoute { .. }))
        .count();
    assert_eq!(
        routes, 1,
        "the occurrence row carries the one route row the definition trace published: {:#?}",
        candidates.candidates
    );
}

/// A reference whose failing segment stays inside the workspace: the status
/// is a plain miss and the trace carries no route out of the workspace.
#[doc(hidden)]
pub fn assert_no_boundary_was_drawn(needle: &str, fixture: &BoundaryFixture) {
    let (outcome, trace) = fixture.trace(needle);
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::NoDefinition,
        "an in-workspace miss stays a plain no-definition: {:?}",
        outcome.diagnostics
    );
    assert!(
        route_rows(&trace).is_empty(),
        "an in-workspace miss reports no route out of the workspace: {:?}",
        trace.candidates
    );
}

/// Compile one authored session pack and activate it against the
/// fixture's analyzer, retaining `discovery` beside it when given.
/// Everything is a session pack in an ephemeral catalog; nothing is
/// installed and nothing is downloaded.
#[track_caller]
#[doc(hidden)]
pub fn activate_fixture_pack(
    fixture: &BoundaryFixture,
    pack_id: &str,
    pack_json: &serde_json::Value,
    evidence: SemanticModelActivationEvidence,
) {
    let catalog = crate::test_support::embedded_session_semantic_pack_fixture(
        pack_id,
        serde_json::to_vec(pack_json).expect("serialize fixture pack"),
    );
    activate_fixture_catalog(fixture, &catalog, pack_id, evidence);
}

#[track_caller]
#[doc(hidden)]
pub fn activate_fixture_catalog(
    fixture: &BoundaryFixture,
    catalog: &crate::analyzer::semantic_model::SemanticPackCatalog,
    pack_id: &str,
    evidence: SemanticModelActivationEvidence,
) {
    let crate::analyzer::semantic_model::SemanticModelRuntimeOutcome::Ready { .. } =
        crate::test_support::activate_semantic_model_fixture(
            fixture.workspace.analyzer(),
            catalog,
            pack_id,
            evidence,
        )
    else {
        panic!("fixture pack must activate");
    };
    assert!(
        fixture
            .workspace
            .analyzer()
            .semantic_model_overlay()
            .is_some(),
        "activation publishes an overlay"
    );
}

/// One declaration-facts pack with a single public type, carrying whatever
/// `members` the caller declares on it.
#[doc(hidden)]
pub fn single_type_pack(
    pack_id: &str,
    language: &str,
    ecosystem: &str,
    package: &str,
    type_id: &str,
    type_name: &str,
    members: serde_json::Value,
) -> serde_json::Value {
    declaration_facts_pack::build(declaration_facts_pack::DeclarationFactsPack {
        pack_id,
        version: "1.0.0",
        producer_name: &format!("{language}-fixture"),
        language,
        ecosystem,
        toolchains: serde_json::json!([]),
        completeness: "complete",
        shard_id: &format!("declarations.{pack_id}"),
        activation: serde_json::json!([{ "package": { "name": package } }]),
        types: serde_json::json!([{
            "id": type_id,
            "name": type_name,
            "type_kind": "class",
            "visibility": "public",
            "hierarchy": [],
            "locator": {
                "kind": "artifact",
                "path": "fixture-source",
                "symbol": type_name
            }
        }]),
        members,
    })
}
