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

pub use crate::analyzer::semantic::partial_flow::fixpoint::CrossedCalls;

pub use crate::analyzer::semantic::partial_flow::fixpoint::ExtendedPartialFlows;

pub use crate::analyzer::semantic::partial_flow::fixpoint::ExtraFlow;

pub use crate::analyzer::semantic::partial_flow::fixpoint::ExtraObservation;

pub use crate::analyzer::semantic::partial_flow::fixpoint::ExtraPhase;

pub use crate::analyzer::semantic::partial_flow::fixpoint::ExtraSeed;

pub use crate::analyzer::semantic::partial_flow::fixpoint::ExtraTarget;

pub use crate::analyzer::semantic::partial_flow::fixpoint::ImplicitHeapRead;

pub use crate::analyzer::semantic::partial_flow::fixpoint::MAX_CROSSED_CLASSES;

pub use crate::analyzer::semantic::partial_flow::fixpoint::ObservationFilter;

pub use crate::analyzer::semantic::partial_flow::fixpoint::PartialFlow;

pub use crate::analyzer::semantic::partial_flow::fixpoint::PartialFlowOutcome;

pub use crate::analyzer::semantic::partial_flow::fixpoint::ProcedurePartialFlows;

pub use crate::analyzer::semantic::partial_flow::fixpoint::SEED_EVENT;

pub use crate::analyzer::semantic::partial_flow::fixpoint::WitnessStep;

pub use crate::analyzer::semantic::partial_flow::fixpoint::caller_exact_read_location;

pub use crate::analyzer::semantic::partial_flow::fixpoint::caller_location_carriers;
pub use crate::analyzer::semantic::partial_flow::fixpoint::caller_returned_member_locator;

pub use crate::analyzer::semantic::partial_flow::fixpoint::compute_partial_flows;

pub use crate::analyzer::semantic::partial_flow::fixpoint::compute_partial_flows_filtered;

pub use crate::analyzer::semantic::partial_flow::fixpoint::compute_partial_flows_with;

pub use crate::analyzer::semantic::partial_flow::fixpoint::compute_partial_flows_with_implicit_reads;

pub use crate::analyzer::semantic::partial_flow::fixpoint::compute_partial_flows_with_edge_kills;

pub use crate::analyzer::semantic::partial_flow::fixpoint::exact_location_covers_read;

pub use crate::analyzer::semantic::partial_flow::fixpoint::input_port_seed;

pub use crate::analyzer::semantic::partial_flow::fixpoint::join_crossed;

pub use crate::analyzer::semantic::partial_flow::fixpoint::observation_value;

pub use crate::analyzer::semantic::partial_flow::ports::HeapSelector;

pub use crate::analyzer::semantic::partial_flow::ports::PartialFlowPort;

pub use crate::analyzer::semantic::partial_flow::ports::PortId;

pub use crate::analyzer::semantic::partial_flow::ports::call_input_value;

pub use crate::analyzer::semantic::partial_flow::ports::heap_selectors;

use std::collections::HashSet;

use crate::analyzer::semantic::workspace_oracle::Interruption;

use crate::analyzer::semantic::workspace_oracle::LocalStoreBases;

use crate::analyzer::semantic::workspace_oracle::RelationProjectionHost;

use crate::analyzer::semantic::workspace_oracle::StrongUpdateStop;

use crate::analyzer::semantic::workspace_oracle::WorkStager;

use crate::analyzer::semantic::workspace_oracle::project_procedure_relations;

use crate::analyzer::semantic::BindingOriginIndex;

use crate::analyzer::semantic::GoPredeclaredBuiltin;

use crate::analyzer::semantic::MemoryLocationId;

use crate::analyzer::semantic::OracleCallContext;

use crate::analyzer::semantic::OracleLimits;

use crate::analyzer::semantic::ProcedureHandle;

use crate::analyzer::semantic::ProgramPointHandle;

use crate::analyzer::semantic::ProgramPointId;

use crate::analyzer::semantic::RuntimeKeyedReadResult;

use crate::analyzer::semantic::SemanticGap;

use crate::analyzer::semantic::SemanticOutcome;

use crate::analyzer::semantic::SemanticProviderError;

use crate::analyzer::semantic::SemanticRequest;

use crate::analyzer::semantic::SemanticWork;

use crate::analyzer::semantic::ValueFlowSnapshot;

use crate::analyzer::semantic::ValueId;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

/// The relation projection's answers from one file alone.
///
/// Every question the file cannot answer gets the conservative answer: no
/// runtime refinements, no discharge and no refuted catch binding. It proves
/// only a closed Rust value object's exact local member overwrite; other
/// stores remain weak without the workspace heap oracle.
#[allow(
    dead_code,
    reason = "the parse-time partial-flow writer will construct the host; the tree is \
              unread because the Rust inert-drop proof resolves names through the \
              workspace and has no file-local form yet"
)]
#[doc(hidden)]
pub struct FileLocalProjectionHost<'a> {
    /// The file's prepared syntax, when the caller holds it.
    #[doc(hidden)]
    pub syntax: Option<&'a PreparedSyntaxTree>,
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
        _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
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
        _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
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
        procedure: &ProcedureHandle,
        _context: &OracleCallContext,
        point: &ProgramPointHandle,
        _event_index: usize,
        location: MemoryLocationId,
        _stored: ValueId,
        bases: &LocalStoreBases,
        _binding_origins: Option<&BindingOriginIndex>,
        _staged: &mut WorkStager,
        _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<bool, StrongUpdateStop> {
        let rust = procedure.semantics().locator().language()
            == crate::analyzer::semantic::SemanticLanguage::Standard(
                brokk_bifrost_core::analyzer::model::Language::Rust,
            );
        let Some(crate::analyzer::semantic::MemoryLocationKind::Field { base, .. }) = procedure
            .semantics()
            .memory_location(location)
            .map(|row| &row.kind)
        else {
            return Ok(false);
        };
        // A field of a closed local may still be a DerefMut projection into
        // shared storage. Rust records that unresolved dispatch at the store
        // point as Calls or FieldMemory, so only a direct-cell store can kill
        // the earlier content. #8918: an escaped borrow also stays open.
        if procedure.semantics().gaps().iter().any(|gap| {
            gap.point == point.id()
                && matches!(
                    gap.capability,
                    crate::analyzer::semantic::SemanticCapability::Calls
                        | crate::analyzer::semantic::SemanticCapability::FieldMemory
                )
        }) {
            return Ok(false);
        }
        Ok(rust
            && ((bases.is_closed_local_object(*base)
                && bases.canonical_base_has_no_secondary_binding_owner(*base))
                || bases.is_closed_local_aggregate_copy_binding(*base)))
    }
}
