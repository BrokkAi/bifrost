//! Per-procedure partial flows: which input ports of one procedure can reach
//! which output ports without passing through a call.
//!
//! The relations come from the same projection the workspace oracle runs,
//! [`project_procedure_relations`]. [`FileLocalProjectionHost`] gives that
//! projection the answers it would otherwise take from the workspace, using
//! only what one file proves.

pub mod fixpoint;
pub mod ports;
pub mod rules;

pub use fixpoint::{
    CrossedCalls, ExtendedPartialFlows, ExtraFlow, ExtraObservation, ExtraPhase, ExtraSeed,
    ExtraTarget, MAX_CROSSED_CLASSES, PartialFlow, PartialFlowOutcome, ProcedurePartialFlows,
    SEED_EVENT, WitnessStep, caller_location_carriers, compute_partial_flows,
    compute_partial_flows_with, input_port_seed, join_crossed,
};
pub use ports::{HeapSelector, PartialFlowPort, PortId, call_input_value, heap_selectors};

use std::collections::HashSet;

use crate::analyzer::semantic::workspace_oracle::{
    Interruption, LocalStoreBases, RelationProjectionHost, StrongUpdateStop, WorkStager,
    project_procedure_relations,
};
use crate::analyzer::semantic::{
    BindingOriginIndex, GoPredeclaredBuiltin, MemoryLocationId, OracleCallContext, OracleLimits,
    ProcedureHandle, ProgramPointHandle, ProgramPointId, RuntimeKeyedReadResult, SemanticGap,
    SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticWork, ValueFlowSnapshot,
    ValueId,
};
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;

/// The relation projection's answers from one file alone.
///
/// Every question the file cannot answer gets the conservative answer: no
/// runtime refinements, no discharge, no refuted catch binding, and no strong
/// update. A store the heap oracle would prove strong is therefore a weak
/// update here, so the projected relations keep the overwritten value alive
/// where the query-time projection would kill it.
#[allow(
    dead_code,
    reason = "the parse-time partial-flow writer will construct the host; the tree is \
              unread because the Rust inert-drop proof resolves names through the \
              workspace and has no file-local form yet"
)]
pub(crate) struct FileLocalProjectionHost<'a> {
    /// The file's prepared syntax, when the caller holds it.
    pub(crate) syntax: Option<&'a PreparedSyntaxTree>,
}

/// The relation snapshot of one procedure projected from its file alone, the
/// same projection the workspace oracle runs with its workspace answers
/// replaced by the file-local ones (see [`FileLocalProjectionHost`]).
pub fn file_local_procedure_relations(
    procedure: &ProcedureHandle,
    context: &OracleCallContext,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<ValueFlowSnapshot>, SemanticProviderError> {
    project_procedure_relations(
        &FileLocalProjectionHost { syntax: None },
        procedure,
        context,
        OracleLimits::default(),
        request,
    )
}

impl RelationProjectionHost for FileLocalProjectionHost<'_> {
    fn runtime_refinements(
        &self,
        _procedure: &ProcedureHandle,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<RuntimeKeyedReadResult>, SemanticProviderError> {
        Ok(SemanticOutcome::Complete {
            value: RuntimeKeyedReadResult::default(),
            work: SemanticWork::default(),
        })
    }

    fn go_builtin_scope_absent(
        &self,
        _procedure: &ProcedureHandle,
        _builtin: GoPredeclaredBuiltin,
        _limit: usize,
        _staged: &mut WorkStager,
        _cancellation: &crate::CancellationToken,
    ) -> Result<bool, Interruption> {
        Ok(false)
    }

    fn refuted_catch_bindings(
        &self,
        _procedure: &ProcedureHandle,
        _request: &SemanticRequest<'_>,
    ) -> Result<HashSet<(ProgramPointId, usize)>, SemanticProviderError> {
        Ok(HashSet::new())
    }

    fn canonical_index_identity_discharged(
        &self,
        _procedure: &ProcedureHandle,
        _context: &OracleCallContext,
        _gap: &SemanticGap,
        _bases: &LocalStoreBases,
        _staged: &mut WorkStager,
        _cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<bool, StrongUpdateStop> {
        Ok(false)
    }

    fn external_constant_field_read_discharged(
        &self,
        _gap: &SemanticGap,
        _procedure: &ProcedureHandle,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<bool, SemanticProviderError> {
        Ok(false)
    }

    fn inert_drop_glue_discharged(
        &self,
        _gap: &SemanticGap,
        _procedure: &ProcedureHandle,
        _request: &mut SemanticRequest<'_>,
        _inert: &mut Option<bool>,
    ) -> Result<bool, SemanticProviderError> {
        Ok(false)
    }

    fn store_holds_strong_update(
        &self,
        _procedure: &ProcedureHandle,
        _context: &OracleCallContext,
        _point: &ProgramPointHandle,
        _event_index: usize,
        _location: MemoryLocationId,
        _stored: ValueId,
        _bases: &LocalStoreBases,
        _binding_origins: Option<&BindingOriginIndex>,
        _staged: &mut WorkStager,
        _cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<bool, StrongUpdateStop> {
        Ok(false)
    }
}

#[cfg(test)]
mod host_tests {
    use super::*;
    use crate::analyzer::semantic::workspace_oracle::project_procedure_relations;
    use crate::analyzer::semantic::{
        OracleLimits, SemanticBudget, ValueFlowOracle, ValueFlowRelationKind,
        WorkspaceSemanticOracle,
    };
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::cancellation::CancellationToken;
    use crate::inline_project::InlineTestProject;

    /// Where no store asks the heap oracle, the file-local host projects the
    /// same relations as the workspace oracle.
    #[test]
    fn file_local_host_projects_the_workspace_relations_without_stores() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "src/lib.rs",
                r#"fn helper(x: i32) -> i32 {
    x
}

fn run(a: i32, flag: bool) -> i32 {
    let b = a;
    let c = if flag { helper(b) } else { b };
    let pair = (c, a);
    pair.0
}
"#,
            )
            .build();
        let file = project.file("src/lib.rs");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("semantic materialization runs")
            .available_value()
            .cloned()
            .expect("the semantic artifact is available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|candidate| {
                candidate
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("run")
            })
            .and_then(|candidate| artifact.procedure_handle(candidate.id()))
            .expect("run is lowered");
        let context = OracleCallContext::empty();

        let oracle = WorkspaceSemanticOracle::new(&analyzer);
        let mut workspace_budget = SemanticBudget::default();
        let workspace = oracle
            .procedure_relations(
                &procedure,
                &context,
                &mut SemanticRequest::new(&mut workspace_budget, &cancellation),
            )
            .expect("workspace projection runs");
        let mut file_budget = SemanticBudget::default();
        let file_local = project_procedure_relations(
            &FileLocalProjectionHost { syntax: None },
            &procedure,
            &context,
            OracleLimits::default(),
            &mut SemanticRequest::new(&mut file_budget, &cancellation),
        )
        .expect("file-local projection runs");

        let workspace = workspace
            .available_value()
            .expect("workspace projection keeps its snapshot")
            .relations();
        let file_local = file_local
            .available_value()
            .expect("file-local projection keeps its snapshot")
            .relations();
        assert!(
            !workspace.is_empty()
                && workspace
                    .iter()
                    .all(|relation| relation.kind != ValueFlowRelationKind::MemoryStore),
            "the fixture projects relations and no store: {workspace:#?}"
        );
        // A relation handle compares by arena identity, and each projection
        // builds its own arena, so compare the record ids instead.
        let comparable = |relations: &[crate::analyzer::semantic::ValueFlowRelation]| {
            relations
                .iter()
                .map(|relation| {
                    let mut relation = relation.clone();
                    let id = relation.id.id();
                    relation.id = workspace[0].id.clone();
                    (id, relation)
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(comparable(workspace), comparable(file_local));
    }
}

/// The relation snapshot of `procedure` projected from its file alone, with
/// the prepared syntax of `file` (spec M2.3). This is the parse-time host of
/// the M2.5 host differential, exposed for that differential only.
#[cfg(any(test, feature = "test-support"))]
pub fn parse_time_procedure_relations(
    workspace: &crate::analyzer::WorkspaceAnalyzer,
    file: &crate::analyzer::ProjectFile,
    procedure: &ProcedureHandle,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<SemanticOutcome<crate::analyzer::semantic::ValueFlowSnapshot>, SemanticProviderError> {
    use crate::analyzer::semantic::workspace_oracle::project_procedure_relations;
    use crate::analyzer::semantic::{OracleLimits, SemanticBudget};

    let syntax = workspace.prepared_syntax_for_test(file);
    let host = FileLocalProjectionHost {
        syntax: syntax.as_deref(),
    };
    let mut budget = SemanticBudget::default();
    project_procedure_relations(
        &host,
        procedure,
        &OracleCallContext::empty(),
        OracleLimits::default(),
        &mut SemanticRequest::new(&mut budget, cancellation),
    )
}

#[cfg(test)]
mod tests;
