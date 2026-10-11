use super::export::CsmiExportError;
use super::import::CsmiImportError;
use super::model::*;
use crate::analyzer::semantic_model::{
    CompiledSummaryMoveInvalidation, CompiledSummaryValuePreservation,
    CompiledSummaryValueTransfer, CompiledSummaryValueTransferKind,
    CompiledSummaryValueTransferLimitation, CompiledSummaryValueTransferLimitationKind,
    CompiledSummaryValueTransferOperation,
};

pub(super) fn compiled_from_csmi(
    payload: CsmiValueTransferAttachment,
    mut member_id: impl FnMut(&str) -> Result<String, CsmiImportError>,
) -> Result<CompiledSummaryValueTransfer, CsmiImportError> {
    let kind = match payload.transfer_kind {
        CsmiValueTransferKind::Copy {} => CompiledSummaryValueTransferKind::Copy {},
        CsmiValueTransferKind::AggregateCopy {} => {
            CompiledSummaryValueTransferKind::AggregateCopy {}
        }
        CsmiValueTransferKind::Move { invalidation } => CompiledSummaryValueTransferKind::Move {
            invalidation: match invalidation {
                CsmiMoveInvalidation::Invalidated => CompiledSummaryMoveInvalidation::Invalidated,
                CsmiMoveInvalidation::Unknown => CompiledSummaryMoveInvalidation::Unknown,
            },
        },
        CsmiValueTransferKind::Conversion { preservation } => {
            CompiledSummaryValueTransferKind::Conversion {
                preservation: match preservation {
                    CsmiValuePreservation::Identity => CompiledSummaryValuePreservation::Identity,
                    CsmiValuePreservation::Preserving => {
                        CompiledSummaryValuePreservation::Preserving
                    }
                    CsmiValuePreservation::Changing => CompiledSummaryValuePreservation::Changing,
                    CsmiValuePreservation::Unknown => CompiledSummaryValuePreservation::Unknown,
                },
            }
        }
        CsmiValueTransferKind::Boxing {} => CompiledSummaryValueTransferKind::Boxing {},
        CsmiValueTransferKind::Unboxing {} => CompiledSummaryValueTransferKind::Unboxing {},
    };
    let operation = match payload.operation {
        CsmiValueTransferOperation::None {} => CompiledSummaryValueTransferOperation::None {},
        CsmiValueTransferOperation::Implicit { symbol } => {
            CompiledSummaryValueTransferOperation::Implicit {
                member: member_id(&symbol)?,
            }
        }
        CsmiValueTransferOperation::Unknown { limitation } => {
            CompiledSummaryValueTransferOperation::Unknown {
                limitation: CompiledSummaryValueTransferLimitation {
                    kind: match limitation.kind {
                        CsmiProfileLimitationKind::BudgetExhausted => {
                            CompiledSummaryValueTransferLimitationKind::BudgetExhausted
                        }
                        CsmiProfileLimitationKind::Cancelled => {
                            CompiledSummaryValueTransferLimitationKind::Cancelled
                        }
                        CsmiProfileLimitationKind::Unsupported => {
                            CompiledSummaryValueTransferLimitationKind::Unsupported
                        }
                        CsmiProfileLimitationKind::UnresolvedIdentity => {
                            CompiledSummaryValueTransferLimitationKind::UnresolvedIdentity
                        }
                        CsmiProfileLimitationKind::AmbiguousIdentity => {
                            CompiledSummaryValueTransferLimitationKind::AmbiguousIdentity
                        }
                        CsmiProfileLimitationKind::IncompleteInput => {
                            CompiledSummaryValueTransferLimitationKind::IncompleteInput
                        }
                        CsmiProfileLimitationKind::Other => {
                            CompiledSummaryValueTransferLimitationKind::Other
                        }
                    },
                    message: limitation.message,
                },
            }
        }
    };
    Ok(CompiledSummaryValueTransfer { kind, operation })
}

pub(super) fn csmi_from_compiled(
    value: &CompiledSummaryValueTransfer,
    mut symbol_id: impl FnMut(&str) -> Result<String, CsmiExportError>,
) -> Result<CsmiValueTransferAttachment, CsmiExportError> {
    let transfer_kind = match value.kind {
        CompiledSummaryValueTransferKind::Copy {} => CsmiValueTransferKind::Copy {},
        CompiledSummaryValueTransferKind::AggregateCopy {} => {
            CsmiValueTransferKind::AggregateCopy {}
        }
        CompiledSummaryValueTransferKind::Move { invalidation } => CsmiValueTransferKind::Move {
            invalidation: match invalidation {
                CompiledSummaryMoveInvalidation::Invalidated => CsmiMoveInvalidation::Invalidated,
                CompiledSummaryMoveInvalidation::Unknown => CsmiMoveInvalidation::Unknown,
            },
        },
        CompiledSummaryValueTransferKind::Conversion { preservation } => {
            CsmiValueTransferKind::Conversion {
                preservation: match preservation {
                    CompiledSummaryValuePreservation::Identity => CsmiValuePreservation::Identity,
                    CompiledSummaryValuePreservation::Preserving => {
                        CsmiValuePreservation::Preserving
                    }
                    CompiledSummaryValuePreservation::Changing => CsmiValuePreservation::Changing,
                    CompiledSummaryValuePreservation::Unknown => CsmiValuePreservation::Unknown,
                },
            }
        }
        CompiledSummaryValueTransferKind::Boxing {} => CsmiValueTransferKind::Boxing {},
        CompiledSummaryValueTransferKind::Unboxing {} => CsmiValueTransferKind::Unboxing {},
    };
    let operation = match &value.operation {
        CompiledSummaryValueTransferOperation::None {} => CsmiValueTransferOperation::None {},
        CompiledSummaryValueTransferOperation::Implicit { member } => {
            CsmiValueTransferOperation::Implicit {
                symbol: symbol_id(member)?,
            }
        }
        CompiledSummaryValueTransferOperation::Unknown { limitation } => {
            CsmiValueTransferOperation::Unknown {
                limitation: CsmiProfileLimitation {
                    kind: match limitation.kind {
                        CompiledSummaryValueTransferLimitationKind::BudgetExhausted => {
                            CsmiProfileLimitationKind::BudgetExhausted
                        }
                        CompiledSummaryValueTransferLimitationKind::Cancelled => {
                            CsmiProfileLimitationKind::Cancelled
                        }
                        CompiledSummaryValueTransferLimitationKind::Unsupported => {
                            CsmiProfileLimitationKind::Unsupported
                        }
                        CompiledSummaryValueTransferLimitationKind::UnresolvedIdentity => {
                            CsmiProfileLimitationKind::UnresolvedIdentity
                        }
                        CompiledSummaryValueTransferLimitationKind::AmbiguousIdentity => {
                            CsmiProfileLimitationKind::AmbiguousIdentity
                        }
                        CompiledSummaryValueTransferLimitationKind::IncompleteInput => {
                            CsmiProfileLimitationKind::IncompleteInput
                        }
                        CompiledSummaryValueTransferLimitationKind::Other => {
                            CsmiProfileLimitationKind::Other
                        }
                    },
                    message: limitation.message.clone(),
                },
            }
        }
    };
    Ok(CsmiValueTransferAttachment {
        kind: CsmiValueTransferAttachmentKind::Transfer,
        transfer_kind,
        operation,
    })
}
