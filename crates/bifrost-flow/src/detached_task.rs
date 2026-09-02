//! Structured values transferred when a call starts in another task.

use crate::analyzer::semantic::{
    CallInvocationMode, CallSiteId, CallableTarget, CallableTargetResolution, CaptureMode,
    CaptureSource, ExecutionTiming, ProcedureSemantics, ProgramPointId, ValueId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetachedTransferRole {
    Receiver,
    Argument,
    Capture,
}

impl DetachedTransferRole {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Receiver => "receiver",
            Self::Argument => "argument",
            Self::Capture => "capture",
        }
    }
}

/// One exact procedure-local value copied into detached work at registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DetachedTaskTransfer {
    pub call_site: CallSiteId,
    /// Registration point where ownership crosses into detached work.
    pub point: ProgramPointId,
    /// Point where the transferred value identity is observed. Receiver and
    /// arguments are observed at registration; a value capture is snapshotted
    /// when its closure environment is created.
    pub observation_point: ProgramPointId,
    pub value: ValueId,
    pub role: DetachedTransferRole,
    pub ordinal: Option<u32>,
}

/// Project detached receiver, argument, and direct immutable closure-capture
/// values from validated semantic rows. The returned order is deterministic:
/// call-site order, receiver, written arguments, then capture-slot order.
pub fn detached_task_transfers(procedure: &ProcedureSemantics) -> Vec<DetachedTaskTransfer> {
    let mut transfers = Vec::new();
    for call in procedure.call_sites().iter().filter(|call| {
        call.invocation_mode == CallInvocationMode::Detached
            && call.execution_timing == ExecutionTiming::DifferentTask
    }) {
        if let Some(value) = call.receiver {
            transfers.push(DetachedTaskTransfer {
                call_site: call.id,
                point: call.point,
                observation_point: call.point,
                value,
                role: DetachedTransferRole::Receiver,
                ordinal: None,
            });
        }
        transfers.extend(
            call.arguments
                .iter()
                .enumerate()
                .map(|(ordinal, argument)| DetachedTaskTransfer {
                    call_site: call.id,
                    point: call.point,
                    observation_point: call.point,
                    value: argument.value,
                    role: DetachedTransferRole::Argument,
                    ordinal: Some(
                        u32::try_from(ordinal).expect("validated call argument count fits in u32"),
                    ),
                }),
        );
        transfers.extend(
            procedure
                .captures()
                .iter()
                .filter(|capture| {
                    (capture.callable == call.callee
                        || matches!(
                            &call.declared_targets,
                            CallableTargetResolution::Proven(CallableTarget::Local(target))
                                if *target == capture.target
                        ))
                        && matches!(capture.mode, CaptureMode::Value | CaptureMode::Move)
                })
                .filter_map(|capture| {
                    let CaptureSource::Value(value) = capture.captured else {
                        return None;
                    };
                    Some(DetachedTaskTransfer {
                        call_site: call.id,
                        point: call.point,
                        observation_point: capture.point,
                        value,
                        role: DetachedTransferRole::Capture,
                        ordinal: Some(capture.destination.get()),
                    })
                }),
        );
    }
    transfers
}
