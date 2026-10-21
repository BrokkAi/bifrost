use crate::analyzer::semantic_model::artifact::*;

use crate::analyzer::semantic_model::model::*;

pub(crate) fn compile_summary_value_transfer(
    transfer: &SummaryValueTransfer,
) -> CompiledSummaryValueTransfer {
    CompiledSummaryValueTransfer {
        kind: match transfer.kind {
            SummaryValueTransferKind::Copy {} => CompiledSummaryValueTransferKind::Copy {},
            SummaryValueTransferKind::AggregateCopy {} => {
                CompiledSummaryValueTransferKind::AggregateCopy {}
            }
            SummaryValueTransferKind::Move { invalidation } => {
                CompiledSummaryValueTransferKind::Move {
                    invalidation: match invalidation {
                        SummaryMoveInvalidation::Invalidated => {
                            CompiledSummaryMoveInvalidation::Invalidated
                        }
                        SummaryMoveInvalidation::Unknown => {
                            CompiledSummaryMoveInvalidation::Unknown
                        }
                    },
                }
            }
            SummaryValueTransferKind::Conversion { preservation } => {
                CompiledSummaryValueTransferKind::Conversion {
                    preservation: match preservation {
                        SummaryValuePreservation::Identity => {
                            CompiledSummaryValuePreservation::Identity
                        }
                        SummaryValuePreservation::Preserving => {
                            CompiledSummaryValuePreservation::Preserving
                        }
                        SummaryValuePreservation::Changing => {
                            CompiledSummaryValuePreservation::Changing
                        }
                        SummaryValuePreservation::Unknown => {
                            CompiledSummaryValuePreservation::Unknown
                        }
                    },
                }
            }
            SummaryValueTransferKind::Boxing {} => CompiledSummaryValueTransferKind::Boxing {},
            SummaryValueTransferKind::Unboxing {} => CompiledSummaryValueTransferKind::Unboxing {},
        },
        operation: match &transfer.operation {
            SummaryValueTransferOperation::None {} => {
                CompiledSummaryValueTransferOperation::None {}
            }
            SummaryValueTransferOperation::Implicit { member } => {
                CompiledSummaryValueTransferOperation::Implicit {
                    member: member.clone(),
                }
            }
            SummaryValueTransferOperation::Unknown { limitation } => {
                CompiledSummaryValueTransferOperation::Unknown {
                    limitation: CompiledSummaryValueTransferLimitation {
                        kind: match limitation.kind {
                            SummaryValueTransferLimitationKind::BudgetExhausted => {
                                CompiledSummaryValueTransferLimitationKind::BudgetExhausted
                            }
                            SummaryValueTransferLimitationKind::Cancelled => {
                                CompiledSummaryValueTransferLimitationKind::Cancelled
                            }
                            SummaryValueTransferLimitationKind::Unsupported => {
                                CompiledSummaryValueTransferLimitationKind::Unsupported
                            }
                            SummaryValueTransferLimitationKind::UnresolvedIdentity => {
                                CompiledSummaryValueTransferLimitationKind::UnresolvedIdentity
                            }
                            SummaryValueTransferLimitationKind::AmbiguousIdentity => {
                                CompiledSummaryValueTransferLimitationKind::AmbiguousIdentity
                            }
                            SummaryValueTransferLimitationKind::IncompleteInput => {
                                CompiledSummaryValueTransferLimitationKind::IncompleteInput
                            }
                            SummaryValueTransferLimitationKind::Other => {
                                CompiledSummaryValueTransferLimitationKind::Other
                            }
                        },
                        message: limitation.message.clone(),
                    },
                }
            }
        },
    }
}

pub(crate) fn compile_result_predicate(
    predicate: AuthoredResultPredicate,
) -> CompiledResultPredicate {
    match predicate {
        AuthoredResultPredicate::Null => CompiledResultPredicate::Null,
        AuthoredResultPredicate::NonNull => CompiledResultPredicate::NonNull,
        AuthoredResultPredicate::True => CompiledResultPredicate::True,
        AuthoredResultPredicate::False => CompiledResultPredicate::False,
        AuthoredResultPredicate::Eof => CompiledResultPredicate::Eof,
        AuthoredResultPredicate::NonZero => CompiledResultPredicate::NonZero,
        AuthoredResultPredicate::MinusOne => CompiledResultPredicate::MinusOne,
    }
}

pub(crate) fn compile_declared_effect(effect: &AuthoredDeclaredEffect) -> CompiledDeclaredEffect {
    CompiledDeclaredEffect {
        id: effect.id.clone(),
        timing: match effect.timing {
            DeclaredEffectTiming::Immediate => CompiledDeclaredEffectTiming::Immediate,
            DeclaredEffectTiming::Deferred => CompiledDeclaredEffectTiming::Deferred,
            DeclaredEffectTiming::Unknown => CompiledDeclaredEffectTiming::Unknown,
        },
        certainty: match effect.certainty {
            DeclaredEffectCertainty::Definite => CompiledDeclaredEffectCertainty::Definite,
            DeclaredEffectCertainty::Possible => CompiledDeclaredEffectCertainty::Possible,
        },
    }
}

pub(crate) fn compile_summary_input(input: &AuthoredSummaryInput) -> CompiledSummaryInput {
    match input {
        AuthoredSummaryInput::Receiver {} => CompiledSummaryInput::Receiver {},
        AuthoredSummaryInput::Parameter { ordinal } => {
            CompiledSummaryInput::Parameter { ordinal: *ordinal }
        }
    }
}

pub(crate) fn compile_concurrency_effect(
    effect: &AuthoredConcurrencyEffect,
) -> CompiledConcurrencyEffect {
    match effect {
        AuthoredConcurrencyEffect::Unsupported { protocol } => {
            CompiledConcurrencyEffect::Unsupported {
                protocol: protocol.clone(),
            }
        }
        AuthoredConcurrencyEffect::TaskSpawn {
            callable,
            group,
            condition,
            timer,
        } => CompiledConcurrencyEffect::TaskSpawn {
            callable: compile_summary_input(callable),
            group: group.as_ref().map(compile_summary_input),
            condition: condition.map(|condition| match condition {
                AuthoredTaskSpawnCondition::CallResultTrue => {
                    CompiledTaskSpawnCondition::CallResultTrue
                }
            }),
            timer: timer.as_ref().map(compile_summary_output),
        },
        AuthoredConcurrencyEffect::TaskJoin { group } => CompiledConcurrencyEffect::TaskJoin {
            group: compile_summary_input(group),
        },
        AuthoredConcurrencyEffect::OnceDo { once, callable } => CompiledConcurrencyEffect::OnceDo {
            once: compile_summary_input(once),
            callable: compile_summary_input(callable),
        },
        AuthoredConcurrencyEffect::LockAcquire {
            lock,
            mode,
            condition,
        } => CompiledConcurrencyEffect::LockAcquire {
            lock: compile_summary_input(lock),
            mode: match mode {
                AuthoredLockMode::Shared => CompiledLockMode::Shared,
                AuthoredLockMode::Exclusive => CompiledLockMode::Exclusive,
            },
            condition: condition.map(|condition| match condition {
                AuthoredLockCondition::CallResultTrue => CompiledLockCondition::CallResultTrue,
            }),
        },
        AuthoredConcurrencyEffect::LockRelease { lock, mode } => {
            CompiledConcurrencyEffect::LockRelease {
                lock: compile_summary_input(lock),
                mode: match mode {
                    AuthoredLockMode::Shared => CompiledLockMode::Shared,
                    AuthoredLockMode::Exclusive => CompiledLockMode::Exclusive,
                },
            }
        }
        AuthoredConcurrencyEffect::WaitGroupAdd { group, delta } => {
            CompiledConcurrencyEffect::WaitGroupAdd {
                group: compile_summary_input(group),
                delta: compile_summary_input(delta),
            }
        }
        AuthoredConcurrencyEffect::WaitGroupDone { group } => {
            CompiledConcurrencyEffect::WaitGroupDone {
                group: compile_summary_input(group),
            }
        }
        AuthoredConcurrencyEffect::WaitGroupWait { group } => {
            CompiledConcurrencyEffect::WaitGroupWait {
                group: compile_summary_input(group),
            }
        }
        AuthoredConcurrencyEffect::Atomic {
            location,
            operation,
        } => CompiledConcurrencyEffect::Atomic {
            location: compile_summary_input(location),
            operation: match operation {
                AuthoredAtomicOperation::Load => CompiledAtomicOperation::Load,
                AuthoredAtomicOperation::Store => CompiledAtomicOperation::Store,
                AuthoredAtomicOperation::ReadModifyWrite => {
                    CompiledAtomicOperation::ReadModifyWrite
                }
            },
        },
        AuthoredConcurrencyEffect::CondBind { condition, lock } => {
            CompiledConcurrencyEffect::CondBind {
                condition: compile_summary_output(condition),
                lock: compile_summary_input(lock),
            }
        }
        AuthoredConcurrencyEffect::CondWait { condition } => CompiledConcurrencyEffect::CondWait {
            condition: compile_summary_input(condition),
        },
        AuthoredConcurrencyEffect::CondNotify { condition, waiters } => {
            CompiledConcurrencyEffect::CondNotify {
                condition: compile_summary_input(condition),
                waiters: match waiters {
                    AuthoredCondWaiters::One => CompiledCondWaiters::One,
                    AuthoredCondWaiters::All => CompiledCondWaiters::All,
                },
            }
        }
        AuthoredConcurrencyEffect::SyncMap {
            map,
            key,
            operation,
        } => CompiledConcurrencyEffect::SyncMap {
            map: compile_summary_input(map),
            key: key.as_ref().map(compile_summary_input),
            operation: match operation {
                AuthoredSyncMapOperation::Store => CompiledSyncMapOperation::Store,
                AuthoredSyncMapOperation::Delete => CompiledSyncMapOperation::Delete,
                AuthoredSyncMapOperation::Clear => CompiledSyncMapOperation::Clear,
                AuthoredSyncMapOperation::Load => CompiledSyncMapOperation::Load,
                AuthoredSyncMapOperation::Range => CompiledSyncMapOperation::Range,
                AuthoredSyncMapOperation::LoadOrStore => CompiledSyncMapOperation::LoadOrStore,
                AuthoredSyncMapOperation::LoadAndDelete => CompiledSyncMapOperation::LoadAndDelete,
                AuthoredSyncMapOperation::Swap => CompiledSyncMapOperation::Swap,
                AuthoredSyncMapOperation::CompareAndSwap => {
                    CompiledSyncMapOperation::CompareAndSwap
                }
                AuthoredSyncMapOperation::CompareAndDelete => {
                    CompiledSyncMapOperation::CompareAndDelete
                }
            },
        },
        AuthoredConcurrencyEffect::TimerStop { timer } => CompiledConcurrencyEffect::TimerStop {
            timer: compile_summary_input(timer),
        },
        AuthoredConcurrencyEffect::TimerReset { timer } => CompiledConcurrencyEffect::TimerReset {
            timer: compile_summary_input(timer),
        },
        AuthoredConcurrencyEffect::ChannelClose { channel, fresh } => {
            CompiledConcurrencyEffect::ChannelClose {
                channel: compile_summary_port(channel),
                fresh: *fresh,
            }
        }
        AuthoredConcurrencyEffect::ChannelCloseAsync { channel, fresh } => {
            CompiledConcurrencyEffect::ChannelCloseAsync {
                channel: compile_summary_port(channel),
                fresh: *fresh,
            }
        }
        AuthoredConcurrencyEffect::ChannelClosePropagate {
            source,
            target,
            target_fresh,
        } => CompiledConcurrencyEffect::ChannelClosePropagate {
            source: compile_summary_port(source),
            target: compile_summary_port(target),
            target_fresh: *target_fresh,
        },
        AuthoredConcurrencyEffect::SubtestRun { callable, group } => {
            CompiledConcurrencyEffect::SubtestRun {
                callable: compile_summary_input(callable),
                group: compile_summary_input(group),
            }
        }
        AuthoredConcurrencyEffect::SubtestParallel { receiver } => {
            CompiledConcurrencyEffect::SubtestParallel {
                receiver: compile_summary_input(receiver),
            }
        }
        AuthoredConcurrencyEffect::SubtestCleanup { callable, group } => {
            CompiledConcurrencyEffect::SubtestCleanup {
                callable: compile_summary_input(callable),
                group: compile_summary_input(group),
            }
        }
    }
}

pub(crate) fn compile_summary_port(port: &AuthoredSummaryPort) -> CompiledSummaryPort {
    match port {
        AuthoredSummaryPort::Input { input } => CompiledSummaryPort::Input {
            input: compile_summary_input(input),
        },
        AuthoredSummaryPort::Output { output } => CompiledSummaryPort::Output {
            output: compile_summary_output(output),
        },
    }
}

pub(crate) fn compile_summary_output(output: &AuthoredSummaryOutput) -> CompiledSummaryOutput {
    match output {
        AuthoredSummaryOutput::NormalReturn {} => CompiledSummaryOutput::NormalReturn {},
        AuthoredSummaryOutput::IndexedNormalReturn { ordinal } => {
            CompiledSummaryOutput::IndexedNormalReturn { ordinal: *ordinal }
        }
        AuthoredSummaryOutput::Receiver {} => CompiledSummaryOutput::Receiver {},
        AuthoredSummaryOutput::Capture { location } => CompiledSummaryOutput::Capture {
            location: location.clone(),
        },
        AuthoredSummaryOutput::Heap { location } => CompiledSummaryOutput::Heap {
            location: location.clone(),
        },
        AuthoredSummaryOutput::ExceptionalReturn {} => CompiledSummaryOutput::ExceptionalReturn {},
    }
}

pub(crate) fn compile_summary_effect(effect: &AuthoredSummaryEffect) -> CompiledSummaryEffect {
    match effect {
        AuthoredSummaryEffect::Allocation { event, output } => CompiledSummaryEffect::Allocation {
            event: event.clone(),
            output: compile_summary_output(output),
        },
        AuthoredSummaryEffect::Call { event, callee } => CompiledSummaryEffect::Call {
            event: event.clone(),
            callee: callee.clone(),
        },
        AuthoredSummaryEffect::Escape { event, input } => CompiledSummaryEffect::Escape {
            event: event.clone(),
            input: compile_summary_input(input),
        },
        AuthoredSummaryEffect::UnknownCall { event, input } => CompiledSummaryEffect::UnknownCall {
            event: event.clone(),
            input: compile_summary_input(input),
        },
        AuthoredSummaryEffect::UnknownCallBoundary { event } => {
            CompiledSummaryEffect::UnknownCallBoundary {
                event: event.clone(),
            }
        }
        AuthoredSummaryEffect::AmbiguousCall {
            event,
            input,
            candidates,
        } => CompiledSummaryEffect::AmbiguousCall {
            event: event.clone(),
            input: compile_summary_input(input),
            candidates: candidates.clone(),
        },
        AuthoredSummaryEffect::Sanitize {
            input,
            output,
            removes,
        } => CompiledSummaryEffect::Sanitize {
            input: compile_summary_input(input),
            output: compile_summary_output(output),
            removes: removes.clone(),
        },
    }
}

#[doc(hidden)]
pub fn authored_summary_value_transfer_from_compiled(
    transfer: &CompiledSummaryValueTransfer,
) -> SummaryValueTransfer {
    SummaryValueTransfer {
        kind: match transfer.kind {
            CompiledSummaryValueTransferKind::Copy {} => SummaryValueTransferKind::Copy {},
            CompiledSummaryValueTransferKind::AggregateCopy {} => {
                SummaryValueTransferKind::AggregateCopy {}
            }
            CompiledSummaryValueTransferKind::Move { invalidation } => {
                SummaryValueTransferKind::Move {
                    invalidation: match invalidation {
                        CompiledSummaryMoveInvalidation::Invalidated => {
                            SummaryMoveInvalidation::Invalidated
                        }
                        CompiledSummaryMoveInvalidation::Unknown => {
                            SummaryMoveInvalidation::Unknown
                        }
                    },
                }
            }
            CompiledSummaryValueTransferKind::Conversion { preservation } => {
                SummaryValueTransferKind::Conversion {
                    preservation: match preservation {
                        CompiledSummaryValuePreservation::Identity => {
                            SummaryValuePreservation::Identity
                        }
                        CompiledSummaryValuePreservation::Preserving => {
                            SummaryValuePreservation::Preserving
                        }
                        CompiledSummaryValuePreservation::Changing => {
                            SummaryValuePreservation::Changing
                        }
                        CompiledSummaryValuePreservation::Unknown => {
                            SummaryValuePreservation::Unknown
                        }
                    },
                }
            }
            CompiledSummaryValueTransferKind::Boxing {} => SummaryValueTransferKind::Boxing {},
            CompiledSummaryValueTransferKind::Unboxing {} => SummaryValueTransferKind::Unboxing {},
        },
        operation: match &transfer.operation {
            CompiledSummaryValueTransferOperation::None {} => {
                SummaryValueTransferOperation::None {}
            }
            CompiledSummaryValueTransferOperation::Implicit { member } => {
                SummaryValueTransferOperation::Implicit {
                    member: member.clone(),
                }
            }
            CompiledSummaryValueTransferOperation::Unknown { limitation } => {
                SummaryValueTransferOperation::Unknown {
                    limitation: SummaryValueTransferLimitation {
                        kind: match limitation.kind {
                            CompiledSummaryValueTransferLimitationKind::BudgetExhausted => {
                                SummaryValueTransferLimitationKind::BudgetExhausted
                            }
                            CompiledSummaryValueTransferLimitationKind::Cancelled => {
                                SummaryValueTransferLimitationKind::Cancelled
                            }
                            CompiledSummaryValueTransferLimitationKind::Unsupported => {
                                SummaryValueTransferLimitationKind::Unsupported
                            }
                            CompiledSummaryValueTransferLimitationKind::UnresolvedIdentity => {
                                SummaryValueTransferLimitationKind::UnresolvedIdentity
                            }
                            CompiledSummaryValueTransferLimitationKind::AmbiguousIdentity => {
                                SummaryValueTransferLimitationKind::AmbiguousIdentity
                            }
                            CompiledSummaryValueTransferLimitationKind::IncompleteInput => {
                                SummaryValueTransferLimitationKind::IncompleteInput
                            }
                            CompiledSummaryValueTransferLimitationKind::Other => {
                                SummaryValueTransferLimitationKind::Other
                            }
                        },
                        message: limitation.message.clone(),
                    },
                }
            }
        },
    }
}

#[doc(hidden)]
pub fn authored_result_predicate_from_compiled(
    predicate: CompiledResultPredicate,
) -> AuthoredResultPredicate {
    match predicate {
        CompiledResultPredicate::Null => AuthoredResultPredicate::Null,
        CompiledResultPredicate::NonNull => AuthoredResultPredicate::NonNull,
        CompiledResultPredicate::True => AuthoredResultPredicate::True,
        CompiledResultPredicate::False => AuthoredResultPredicate::False,
        CompiledResultPredicate::Eof => AuthoredResultPredicate::Eof,
        CompiledResultPredicate::NonZero => AuthoredResultPredicate::NonZero,
        CompiledResultPredicate::MinusOne => AuthoredResultPredicate::MinusOne,
    }
}

#[doc(hidden)]
pub fn authored_declared_effect_from_compiled(
    effect: &CompiledDeclaredEffect,
) -> AuthoredDeclaredEffect {
    AuthoredDeclaredEffect {
        id: effect.id.clone(),
        timing: match effect.timing {
            CompiledDeclaredEffectTiming::Immediate => DeclaredEffectTiming::Immediate,
            CompiledDeclaredEffectTiming::Deferred => DeclaredEffectTiming::Deferred,
            CompiledDeclaredEffectTiming::Unknown => DeclaredEffectTiming::Unknown,
        },
        certainty: match effect.certainty {
            CompiledDeclaredEffectCertainty::Definite => DeclaredEffectCertainty::Definite,
            CompiledDeclaredEffectCertainty::Possible => DeclaredEffectCertainty::Possible,
        },
    }
}

#[doc(hidden)]
pub fn authored_summary_input_from_compiled(input: &CompiledSummaryInput) -> AuthoredSummaryInput {
    match input {
        CompiledSummaryInput::Receiver {} => AuthoredSummaryInput::Receiver {},
        CompiledSummaryInput::Parameter { ordinal } => {
            AuthoredSummaryInput::Parameter { ordinal: *ordinal }
        }
    }
}

#[doc(hidden)]
pub fn authored_concurrency_effect_from_compiled(
    effect: &CompiledConcurrencyEffect,
) -> AuthoredConcurrencyEffect {
    match effect {
        CompiledConcurrencyEffect::Unsupported { protocol } => {
            AuthoredConcurrencyEffect::Unsupported {
                protocol: protocol.clone(),
            }
        }
        CompiledConcurrencyEffect::TaskSpawn {
            callable,
            group,
            condition,
            timer,
        } => AuthoredConcurrencyEffect::TaskSpawn {
            callable: authored_summary_input_from_compiled(callable),
            group: group.as_ref().map(authored_summary_input_from_compiled),
            condition: condition.map(|condition| match condition {
                CompiledTaskSpawnCondition::CallResultTrue => {
                    AuthoredTaskSpawnCondition::CallResultTrue
                }
            }),
            timer: timer.as_ref().map(authored_summary_output_from_compiled),
        },
        CompiledConcurrencyEffect::TaskJoin { group } => AuthoredConcurrencyEffect::TaskJoin {
            group: authored_summary_input_from_compiled(group),
        },
        CompiledConcurrencyEffect::OnceDo { once, callable } => AuthoredConcurrencyEffect::OnceDo {
            once: authored_summary_input_from_compiled(once),
            callable: authored_summary_input_from_compiled(callable),
        },
        CompiledConcurrencyEffect::LockAcquire {
            lock,
            mode,
            condition,
        } => AuthoredConcurrencyEffect::LockAcquire {
            lock: authored_summary_input_from_compiled(lock),
            mode: match mode {
                CompiledLockMode::Shared => AuthoredLockMode::Shared,
                CompiledLockMode::Exclusive => AuthoredLockMode::Exclusive,
            },
            condition: condition.map(|condition| match condition {
                CompiledLockCondition::CallResultTrue => AuthoredLockCondition::CallResultTrue,
            }),
        },
        CompiledConcurrencyEffect::LockRelease { lock, mode } => {
            AuthoredConcurrencyEffect::LockRelease {
                lock: authored_summary_input_from_compiled(lock),
                mode: match mode {
                    CompiledLockMode::Shared => AuthoredLockMode::Shared,
                    CompiledLockMode::Exclusive => AuthoredLockMode::Exclusive,
                },
            }
        }
        CompiledConcurrencyEffect::WaitGroupAdd { group, delta } => {
            AuthoredConcurrencyEffect::WaitGroupAdd {
                group: authored_summary_input_from_compiled(group),
                delta: authored_summary_input_from_compiled(delta),
            }
        }
        CompiledConcurrencyEffect::WaitGroupDone { group } => {
            AuthoredConcurrencyEffect::WaitGroupDone {
                group: authored_summary_input_from_compiled(group),
            }
        }
        CompiledConcurrencyEffect::WaitGroupWait { group } => {
            AuthoredConcurrencyEffect::WaitGroupWait {
                group: authored_summary_input_from_compiled(group),
            }
        }
        CompiledConcurrencyEffect::Atomic {
            location,
            operation,
        } => AuthoredConcurrencyEffect::Atomic {
            location: authored_summary_input_from_compiled(location),
            operation: match operation {
                CompiledAtomicOperation::Load => AuthoredAtomicOperation::Load,
                CompiledAtomicOperation::Store => AuthoredAtomicOperation::Store,
                CompiledAtomicOperation::ReadModifyWrite => {
                    AuthoredAtomicOperation::ReadModifyWrite
                }
            },
        },
        CompiledConcurrencyEffect::CondBind { condition, lock } => {
            AuthoredConcurrencyEffect::CondBind {
                condition: authored_summary_output_from_compiled(condition),
                lock: authored_summary_input_from_compiled(lock),
            }
        }
        CompiledConcurrencyEffect::CondWait { condition } => AuthoredConcurrencyEffect::CondWait {
            condition: authored_summary_input_from_compiled(condition),
        },
        CompiledConcurrencyEffect::CondNotify { condition, waiters } => {
            AuthoredConcurrencyEffect::CondNotify {
                condition: authored_summary_input_from_compiled(condition),
                waiters: match waiters {
                    CompiledCondWaiters::One => AuthoredCondWaiters::One,
                    CompiledCondWaiters::All => AuthoredCondWaiters::All,
                },
            }
        }
        CompiledConcurrencyEffect::SyncMap {
            map,
            key,
            operation,
        } => AuthoredConcurrencyEffect::SyncMap {
            map: authored_summary_input_from_compiled(map),
            key: key.as_ref().map(authored_summary_input_from_compiled),
            operation: match operation {
                CompiledSyncMapOperation::Store => AuthoredSyncMapOperation::Store,
                CompiledSyncMapOperation::Delete => AuthoredSyncMapOperation::Delete,
                CompiledSyncMapOperation::Clear => AuthoredSyncMapOperation::Clear,
                CompiledSyncMapOperation::Load => AuthoredSyncMapOperation::Load,
                CompiledSyncMapOperation::Range => AuthoredSyncMapOperation::Range,
                CompiledSyncMapOperation::LoadOrStore => AuthoredSyncMapOperation::LoadOrStore,
                CompiledSyncMapOperation::LoadAndDelete => AuthoredSyncMapOperation::LoadAndDelete,
                CompiledSyncMapOperation::Swap => AuthoredSyncMapOperation::Swap,
                CompiledSyncMapOperation::CompareAndSwap => {
                    AuthoredSyncMapOperation::CompareAndSwap
                }
                CompiledSyncMapOperation::CompareAndDelete => {
                    AuthoredSyncMapOperation::CompareAndDelete
                }
            },
        },
        CompiledConcurrencyEffect::TimerStop { timer } => AuthoredConcurrencyEffect::TimerStop {
            timer: authored_summary_input_from_compiled(timer),
        },
        CompiledConcurrencyEffect::TimerReset { timer } => AuthoredConcurrencyEffect::TimerReset {
            timer: authored_summary_input_from_compiled(timer),
        },
        CompiledConcurrencyEffect::ChannelClose { channel, fresh } => {
            AuthoredConcurrencyEffect::ChannelClose {
                channel: authored_summary_port_from_compiled(channel),
                fresh: *fresh,
            }
        }
        CompiledConcurrencyEffect::ChannelCloseAsync { channel, fresh } => {
            AuthoredConcurrencyEffect::ChannelCloseAsync {
                channel: authored_summary_port_from_compiled(channel),
                fresh: *fresh,
            }
        }
        CompiledConcurrencyEffect::ChannelClosePropagate {
            source,
            target,
            target_fresh,
        } => AuthoredConcurrencyEffect::ChannelClosePropagate {
            source: authored_summary_port_from_compiled(source),
            target: authored_summary_port_from_compiled(target),
            target_fresh: *target_fresh,
        },
        CompiledConcurrencyEffect::SubtestRun { callable, group } => {
            AuthoredConcurrencyEffect::SubtestRun {
                callable: authored_summary_input_from_compiled(callable),
                group: authored_summary_input_from_compiled(group),
            }
        }
        CompiledConcurrencyEffect::SubtestParallel { receiver } => {
            AuthoredConcurrencyEffect::SubtestParallel {
                receiver: authored_summary_input_from_compiled(receiver),
            }
        }
        CompiledConcurrencyEffect::SubtestCleanup { callable, group } => {
            AuthoredConcurrencyEffect::SubtestCleanup {
                callable: authored_summary_input_from_compiled(callable),
                group: authored_summary_input_from_compiled(group),
            }
        }
    }
}

pub(crate) fn authored_summary_port_from_compiled(
    port: &CompiledSummaryPort,
) -> AuthoredSummaryPort {
    match port {
        CompiledSummaryPort::Input { input } => AuthoredSummaryPort::Input {
            input: authored_summary_input_from_compiled(input),
        },
        CompiledSummaryPort::Output { output } => AuthoredSummaryPort::Output {
            output: authored_summary_output_from_compiled(output),
        },
    }
}

#[doc(hidden)]
pub fn authored_summary_output_from_compiled(
    output: &CompiledSummaryOutput,
) -> AuthoredSummaryOutput {
    match output {
        CompiledSummaryOutput::NormalReturn {} => AuthoredSummaryOutput::NormalReturn {},
        CompiledSummaryOutput::IndexedNormalReturn { ordinal } => {
            AuthoredSummaryOutput::IndexedNormalReturn { ordinal: *ordinal }
        }
        CompiledSummaryOutput::Receiver {} => AuthoredSummaryOutput::Receiver {},
        CompiledSummaryOutput::Capture { location } => AuthoredSummaryOutput::Capture {
            location: location.clone(),
        },
        CompiledSummaryOutput::Heap { location } => AuthoredSummaryOutput::Heap {
            location: location.clone(),
        },
        CompiledSummaryOutput::ExceptionalReturn {} => AuthoredSummaryOutput::ExceptionalReturn {},
    }
}

#[doc(hidden)]
pub fn authored_summary_effect_from_compiled(
    effect: &CompiledSummaryEffect,
) -> AuthoredSummaryEffect {
    match effect {
        CompiledSummaryEffect::Allocation { event, output } => AuthoredSummaryEffect::Allocation {
            event: event.clone(),
            output: authored_summary_output_from_compiled(output),
        },
        CompiledSummaryEffect::Call { event, callee } => AuthoredSummaryEffect::Call {
            event: event.clone(),
            callee: callee.clone(),
        },
        CompiledSummaryEffect::Escape { event, input } => AuthoredSummaryEffect::Escape {
            event: event.clone(),
            input: authored_summary_input_from_compiled(input),
        },
        CompiledSummaryEffect::UnknownCall { event, input } => AuthoredSummaryEffect::UnknownCall {
            event: event.clone(),
            input: authored_summary_input_from_compiled(input),
        },
        CompiledSummaryEffect::UnknownCallBoundary { event } => {
            AuthoredSummaryEffect::UnknownCallBoundary {
                event: event.clone(),
            }
        }
        CompiledSummaryEffect::AmbiguousCall {
            event,
            input,
            candidates,
        } => AuthoredSummaryEffect::AmbiguousCall {
            event: event.clone(),
            input: authored_summary_input_from_compiled(input),
            candidates: candidates.clone(),
        },
        CompiledSummaryEffect::Sanitize {
            input,
            output,
            removes,
        } => AuthoredSummaryEffect::Sanitize {
            input: authored_summary_input_from_compiled(input),
            output: authored_summary_output_from_compiled(output),
            removes: removes.clone(),
        },
    }
}
