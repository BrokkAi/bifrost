//! Integer codes for every enumeration the semantic IR rows carry.
//!
//! A code is the variant's zero-based position in its Rust declaration. A
//! fieldless enum implements [`RowCode`] directly, and its code is the
//! discriminant the language assigns. An enum whose variants carry data gets
//! a fieldless tag enum here, listed in the same declaration order; the
//! encoder takes the tag of a value and the decoder matches on the tag to
//! rebuild the payload from the row's other columns.

use crate::analyzer::semantic::{
    AccessPathTail, AllocationKind, ArgumentDomain, AsyncResumeKind, BackingStoreOffset,
    CallArgumentExpansion, CallContinuationKind, CallInvocationMode, CallableReferenceKind,
    CallableTarget, CallableTargetResolution, CaptureMode, CaptureSource, ConstructionReturn,
    ControlContinuation, ControlEdgeKind, DeclarationSegmentKind, DispatchExtensibility,
    DropBehavior, EvidenceCompleteness, ExecutionTiming, FormalMultiplicity,
    FormalParameterPassingMode, GuardPredicate, IndexedLocationIdentity, IntegerComparison,
    LifecycleIncompleteReason, MemoryAccessKind, MemoryLocationKind, MemoryValueCopy,
    MoveInvalidation, MoveOutState, PointerAccessKind, PointerAccessWidth, PointerByteOffset,
    PointerIncompleteReason, PointerInvalidationCause, PointerInvalidationTarget,
    PointerOriginKind, PointerRelationStrength, ProcedureCallBoundary, ProcedureInvocationKind,
    ProcedureKind, ProcedureReceiverBinding, ProofStatus, ScopeEndAt, SemanticBudgetDimension,
    SemanticCapability, SemanticEffect, SemanticGapDischarge, SemanticGapKind, SemanticGapSubject,
    SemanticIncompleteReason, SemanticIncompleteSubject, SemanticPlace, SemanticRole,
    SemanticValueKind, SourceMappingKind, SwitchFactKind, SwitchSelectorDomain,
    SynchronizationOperation, SynchronizationPayload, SynchronizationPayloadCopy, TransferKind,
    TransferOperation, ValueFlowKind, ValuePreservation, ValueUseKind,
};

use super::SemanticIrLoweringOutcome;
use crate::analyzer::semantic::partial_flow::fixpoint::PartialFlowOutcome;
use crate::analyzer::semantic::partial_flow::ports::{HeapSelector, PartialFlowPort};

/// A fieldless enumeration stored as its declaration position.
pub(super) trait RowCode: Copy + PartialEq + std::fmt::Debug + 'static {
    /// Every variant, in declaration order.
    const VARIANTS: &'static [Self];

    fn code(self) -> i64;

    fn try_from_code(code: i64) -> Option<Self> {
        usize::try_from(code)
            .ok()
            .and_then(|index| Self::VARIANTS.get(index))
            .copied()
    }
}

macro_rules! fieldless_codes {
    ($($ty:ident { $($variant:ident),+ $(,)? })+) => {
        $(
            impl RowCode for $ty {
                const VARIANTS: &'static [Self] = &[$($ty::$variant),+];

                fn code(self) -> i64 {
                    // The match keeps the variant list exhaustive; the
                    // discriminant is the declaration position.
                    match self {
                        $($ty::$variant)|+ => self as i64,
                    }
                }
            }
        )+
    };
}

fieldless_codes! {
    AccessPathTail { Exact, Summary }
    PartialFlowOutcome { Complete, Truncated, ExceededBudget, Error }
    ProcedureKind {
        Function, Method, Constructor, Initializer, LocalFunction, Lambda, Closure, Accessor,
        Operator,
    }
    ProcedureInvocationKind { Immediate, Deferred }
    DispatchExtensibility { Open, Closed }
    ProcedureCallBoundary { Direct, Unknown }
    ProcedureReceiverBinding { Instance, Class }
    ConstructionReturn { MayReplaceAllocation, PreservesAllocation }
    FormalParameterPassingMode { PositionalOnly, PositionalOrNamed, NamedOnly }
    CallInvocationMode { Ordinary, Detached }
    ExecutionTiming {
        SameEvaluation, SameInvocation, LaterSameTurn, AfterSuspension, DifferentTask,
        DifferentThread, DeferredCallback, GeneratorResume, CancellationCleanup, Unknown,
    }
    SourceMappingKind { Exact, Enclosing, Synthetic }
    SemanticGapKind { Ambiguous, Unknown, Unsupported, Unproven, ExceededBudget }
    SemanticCapability {
        Procedures, EntryBoundary, NormalExitBoundary, ExceptionalExitBoundary, BasicBlocks,
        ProgramPoints, NormalControlFlow, ExceptionalControlFlow, CleanupControlFlow,
        Assignments, Values, Allocations, LocalFlow, ParameterFlow, ReceiverFlow, ReturnFlow,
        FieldMemory, StaticMemory, IndexMemory, Calls, DynamicDispatch, NormalCallContinuation,
        ExceptionalCallContinuation, Captures, CallableReferences, AsyncSuspendResume,
        GeneratorSuspension, DeferredExecution, ConcurrentSpawn, Synchronization,
        NonLocalControl, ResourceManagement, GuardFacts, SwitchFacts,
    }
    SemanticGapDischarge {
        None, CallResolution, RetainedEvaluationOrder, RetainedControlTopology,
        CanonicalIndexIdentity, ExactFieldLayout, RuntimeReadBehavior,
        NonRejoiningExceptionalExit, ExitOnlyProcedureCompletion, ModeledEffectPartition,
        RebindAtCallOrSuspension, InertDropGlue, NonRejoiningExceptionalExitAfterInertDrops,
    }
    SemanticBudgetDimension {
        SourceBytes, Procedures, Blocks, ProgramPoints, Values, Allocations, CallSites,
        MemoryLocations, Captures, SourceMappings, Evidence, Gaps, Events, ControlEdges,
        NestedEntries, OwnedTextBytes,
    }
    IndexedLocationIdentity { Element, Aggregate }
    MoveInvalidation { Invalidated, Unknown }
    ValuePreservation { Identity, Preserving, Changing }
    ValueUseKind { Dereference, Unbind }
    MemoryAccessKind { Field, Property, Static, Index, Dereference, LexicalCell, Capture }
    SynchronizationOperation { ChannelSend, ChannelReceive, ChannelClose }
    CallContinuationKind { Normal, Exceptional }
    AsyncResumeKind { Normal, Exceptional }
    ControlEdgeKind {
        Normal, ConditionalTrue, ConditionalFalse, SwitchCase, LoopBack, Exceptional, Cleanup,
        AsyncNormal, AsyncExceptional,
    }
    IntegerComparison { LessThan, LessThanOrEqual, GreaterThan, GreaterThanOrEqual }
    SwitchFactKind { Expression, Expressionless, Type }
    SwitchSelectorDomain { Boolean, Open }
    MoveOutState { Uninitialized, PartiallyInitialized, Unknown }
    PointerRelationStrength { Must, May }
    PointerAccessKind { Read, Write, ReadWrite }
    PointerInvalidationCause {
        Deallocated, OwnerDropped, OwnershipTransferred, PossibleReallocation,
    }
    LifecycleIncompleteReason {
        UnsupportedMacroExpansion, GenericDropObligation, MissingType, PartialMove,
        ManuallyDrop, ForgottenOwner, UnresolvedTraitDispatch, UnsupportedCleanup,
        UnknownPanicStrategy, AsyncCancellationState,
    }
    PointerIncompleteReason {
        RawPointerType, UnsupportedOperation, MissingType, UnknownLayout,
        UnknownAllocationExtent, AmbiguousOrigin, AmbiguousAlias, UnresolvedAllocator,
        ExternalEscape, OffsetOverflow,
    }
    DeclarationSegmentKind {
        File, Namespace, Type, Function, Method, Constructor, Initializer, LocalFunction,
        Lambda, Closure, AnonymousCallable,
    }
    SemanticRole {
        Artifact, Procedure, Block, ProgramPoint, Value, Allocation, CallSite, MemoryLocation,
        Capture, SourceMapping, Evidence, Gap,
    }
}

macro_rules! payload_tags {
    ($($tag:ident for $ty:ident { $($variant:ident),+ $(,)? })+) => {
        $(
            /// The variant of one data-carrying enumeration, in its
            /// declaration order.
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub(super) enum $tag {
                $($variant),+
            }

            impl $tag {
                pub(super) fn of(value: &$ty) -> Self {
                    match value {
                        $($ty::$variant { .. } => Self::$variant),+
                    }
                }
            }

            impl RowCode for $tag {
                const VARIANTS: &'static [Self] = &[$(Self::$variant),+];

                fn code(self) -> i64 {
                    self as i64
                }
            }
        )+
    };
}

payload_tags! {
    PartialPortTag for PartialFlowPort {
        Receiver, Parameter, NormalReturn, IndexedNormalReturn, ExceptionalReturn, CallReceiver,
        CallArgument, CallResult, CallThrown, Capture, Heap, CaptureOut,
    }
    HeapSelectorTag for HeapSelector { Field, Property, ConstantIndex, ExactIndex, AnyIndex }
    ValueKindTag for SemanticValueKind {
        Local, Parameter, DefaultArgument, Receiver, Return, Temporary, Address, Null, Boolean,
        UnsignedInteger, SignedInteger, FloatingPoint, Constant, ConstantString, Exception,
        Callable, AwaitResult, LanguageDefined,
    }
    MultiplicityTag for FormalMultiplicity { One, Rest }
    ArgumentDomainTag for ArgumentDomain {
        Positional, Keyword, PositionalOrKeyword, LanguageDefined,
    }
    ExpansionTag for CallArgumentExpansion { Unclassified, Direct, Spread }
    AllocationKindTag for AllocationKind {
        Object, Array, Slice, Callable, ClosureEnvironment, SharedCell, LanguageDefined,
    }
    MemoryLocationKindTag for MemoryLocationKind {
        Field, Property, Static, Index, Dereference, LexicalCell, Capture,
    }
    MemoryValueCopyTag for MemoryValueCopy { Unknown, Value, Reference, BackingStore }
    CaptureModeTag for CaptureMode {
        Value, Move, SharedCell, MutableCell, Receiver, LanguageDefined, Unknown,
    }
    CaptureSourceTag for CaptureSource { Value, Location }
    CallableTargetTag for CallableTarget { Local, Unmaterialized, External, Artifact }
    TargetResolutionTag for CallableTargetResolution {
        Proven, Ambiguous, Unknown, Unsupported, Unproven, ExceededBudget,
    }
    ContinuationTag for ControlContinuation {
        Target, Absent, Unknown, Unsupported, Unproven, ExceededBudget,
    }
    ProofTag for ProofStatus { Proven, Unproven }
    CompletenessTag for EvidenceCompleteness { Complete, Partial }
    GapSubjectTag for SemanticGapSubject {
        Procedure, Point, Value, MemoryLocation, Capture, CallSite, CallContinuation,
        AsyncContinuation,
    }
    EffectTag for SemanticEffect {
        Entry, NormalExit, ExceptionalExit, Assignment, AggregateInitializer, ValueFlow,
        ValueUse, Allocation, MemoryLoad, MemoryStore, Synchronization, CallableCreation,
        CallableReference, CaptureBind, Invoke, CallContinuation, ProcedureReturn, Throw,
        AsyncSuspend, AsyncResume, Gap,
    }
    ValueFlowKindTag for ValueFlowKind {
        Local, Transfer, BackingStore, IntegerOffset, BackingStoreAlternative, Parameter,
        Receiver, Return, IndexedReturn, ReferenceBoxing, ReferenceUnboxing, LanguageDefined,
    }
    TransferKindTag for TransferKind {
        Copy, AggregateCopy, Move, Conversion, Boxing, Unboxing,
    }
    TransferOperationTag for TransferOperation {
        None, CallSite, CallArgumentConversion, ValueCarrierAdaptation, Unknown,
    }
    BackingStoreOffsetTag for BackingStoreOffset { Zero, Constant, Value }
    CallableReferenceKindTag for CallableReferenceKind {
        Lambda, Function, BoundMethod, UnboundMethod, ModuleQualified, TypeQualifiedMethod,
        StaticMethod, Constructor,
    }
    SynchronizationPayloadTag for SynchronizationPayload { Send, Receive }
    SynchronizationPayloadCopyTag for SynchronizationPayloadCopy {
        Unknown, Reference, BackingStore,
    }
    GuardPredicateTag for GuardPredicate {
        ConstantBoolean, NullComparison, ConstantEquality, OrderedIntegerComparison,
        OrderedFloatComparison, NanComparison, InstanceOf, ExactClass, HasMember, Truthy,
        Opaque,
    }
    PlaceTag for SemanticPlace { LocalBinding, MemoryLocation }
    DropBehaviorTag for DropBehavior { Trivial, Destructor }
    ScopeEndAtTag for ScopeEndAt { Point, Edge }
    PointerOriginKindTag for PointerOriginKind { StackPlace, Allocation }
    PointerByteOffsetTag for PointerByteOffset { Exact, Value, Range, Unknown }
    PointerAccessWidthTag for PointerAccessWidth { Exact, ValueTimes, Unknown }
    PointerInvalidationTargetTag for PointerInvalidationTarget { Pointer, Origin }
    IncompleteSubjectTag for SemanticIncompleteSubject {
        Procedure, Place, Value, PointerOrigin,
    }
    IncompleteReasonTag for SemanticIncompleteReason { Lifecycle, Pointer }
    OutcomeTag for SemanticIrLoweringOutcome {
        Complete, ExceededBudget, Unsupported, Incomplete, Error, Panicked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip every variant of one coded enumeration and compare its
    /// largest code with the CHECK bound the M1.2 specification states for
    /// the column that stores it. `None` marks a column the specification
    /// gives no CHECK.
    fn assert_codes<T: RowCode>(bound: Option<i64>) {
        for (position, variant) in T::VARIANTS.iter().enumerate() {
            let code = variant.code();
            assert_eq!(
                code,
                i64::try_from(position).unwrap(),
                "{variant:?} is listed out of declaration order"
            );
            assert_eq!(T::try_from_code(code), Some(*variant));
        }
        let count = i64::try_from(T::VARIANTS.len()).unwrap();
        assert_eq!(T::try_from_code(count), None);
        assert_eq!(T::try_from_code(-1), None);
        if let Some(bound) = bound {
            assert_eq!(
                count - 1,
                bound,
                "{} has {count} variants but its column is CHECKed 0..{bound}",
                std::any::type_name::<T>()
            );
        }
    }

    #[test]
    fn semantic_ir_codes_round_trip_and_match_check_bounds() {
        assert_codes::<ProcedureKind>(Some(8));
        assert_codes::<ProcedureInvocationKind>(Some(1));
        assert_codes::<DispatchExtensibility>(Some(1));
        assert_codes::<ProcedureCallBoundary>(Some(1));
        assert_codes::<ProcedureReceiverBinding>(Some(1));
        assert_codes::<ConstructionReturn>(Some(1));
        assert_codes::<FormalParameterPassingMode>(Some(2));
        assert_codes::<CallInvocationMode>(Some(1));
        assert_codes::<ExecutionTiming>(Some(9));
        assert_codes::<SourceMappingKind>(Some(2));
        assert_codes::<SemanticGapKind>(Some(4));
        assert_codes::<SemanticCapability>(Some(33));
        assert_codes::<SemanticGapDischarge>(Some(12));
        assert_codes::<SemanticBudgetDimension>(Some(15));
        assert_codes::<IndexedLocationIdentity>(Some(1));
        assert_codes::<MoveInvalidation>(None);
        assert_codes::<ValuePreservation>(None);
        assert_codes::<ValueUseKind>(None);
        assert_codes::<MemoryAccessKind>(None);
        assert_codes::<SynchronizationOperation>(None);
        assert_codes::<CallContinuationKind>(None);
        assert_codes::<AsyncResumeKind>(None);
        assert_codes::<ControlEdgeKind>(Some(8));
        assert_codes::<IntegerComparison>(Some(3));
        assert_codes::<SwitchFactKind>(Some(2));
        assert_codes::<SwitchSelectorDomain>(Some(1));
        assert_codes::<MoveOutState>(Some(2));
        assert_codes::<PointerRelationStrength>(Some(1));
        assert_codes::<PointerAccessKind>(Some(2));
        assert_codes::<PointerInvalidationCause>(Some(3));
        assert_codes::<LifecycleIncompleteReason>(Some(9));
        assert_codes::<PointerIncompleteReason>(Some(9));
        assert_codes::<DeclarationSegmentKind>(Some(10));
        assert_codes::<SemanticRole>(Some(11));
        assert_codes::<AccessPathTail>(Some(1));
        assert_codes::<PartialFlowOutcome>(Some(3));

        assert_codes::<PartialPortTag>(Some(11));
        assert_codes::<HeapSelectorTag>(Some(4));
        assert_codes::<ValueKindTag>(Some(17));
        assert_codes::<MultiplicityTag>(Some(1));
        assert_codes::<ArgumentDomainTag>(Some(3));
        assert_codes::<ExpansionTag>(Some(2));
        assert_codes::<AllocationKindTag>(Some(6));
        assert_codes::<MemoryLocationKindTag>(Some(6));
        assert_codes::<MemoryValueCopyTag>(Some(3));
        assert_codes::<CaptureModeTag>(Some(6));
        assert_codes::<CaptureSourceTag>(Some(1));
        assert_codes::<CallableTargetTag>(Some(3));
        assert_codes::<TargetResolutionTag>(Some(5));
        assert_codes::<ContinuationTag>(Some(5));
        assert_codes::<ProofTag>(Some(1));
        assert_codes::<CompletenessTag>(Some(1));
        assert_codes::<GapSubjectTag>(Some(7));
        assert_codes::<EffectTag>(Some(20));
        assert_codes::<ValueFlowKindTag>(None);
        assert_codes::<TransferKindTag>(Some(5));
        assert_codes::<TransferOperationTag>(Some(4));
        assert_codes::<BackingStoreOffsetTag>(Some(2));
        assert_codes::<CallableReferenceKindTag>(None);
        assert_codes::<SynchronizationPayloadTag>(Some(1));
        assert_codes::<SynchronizationPayloadCopyTag>(Some(2));
        assert_codes::<GuardPredicateTag>(Some(10));
        assert_codes::<PlaceTag>(Some(1));
        assert_codes::<DropBehaviorTag>(Some(1));
        assert_codes::<ScopeEndAtTag>(Some(1));
        assert_codes::<PointerOriginKindTag>(Some(1));
        assert_codes::<PointerByteOffsetTag>(Some(3));
        assert_codes::<PointerAccessWidthTag>(Some(2));
        assert_codes::<PointerInvalidationTargetTag>(Some(1));
        assert_codes::<IncompleteSubjectTag>(Some(3));
        assert_codes::<IncompleteReasonTag>(Some(1));
        assert_codes::<OutcomeTag>(Some(5));
    }

    /// A tag's order cannot be checked against its declaration by the
    /// compiler. Where the IR publishes its labels in declaration order, the
    /// tag order must agree with them.
    #[test]
    fn semantic_ir_payload_tags_follow_published_label_order() {
        let samples = [
            GuardPredicate::ConstantBoolean { value: true },
            GuardPredicate::NullComparison { null_on_true: true },
            GuardPredicate::ConstantEquality {
                negated: false,
                constant: crate::analyzer::semantic::ValueId::new(0),
            },
            GuardPredicate::OrderedIntegerComparison {
                relation: IntegerComparison::LessThan,
                constant: crate::analyzer::semantic::ValueId::new(0),
            },
            GuardPredicate::OrderedFloatComparison {
                relation: IntegerComparison::LessThan,
                constant: crate::analyzer::semantic::ValueId::new(0),
            },
            GuardPredicate::NanComparison { nan_on_true: true },
            GuardPredicate::InstanceOf {
                value: crate::analyzer::semantic::ValueId::new(0),
                classes: crate::analyzer::semantic::ValueId::new(1),
            },
            GuardPredicate::ExactClass {
                value: crate::analyzer::semantic::ValueId::new(0),
                classes: crate::analyzer::semantic::ValueId::new(1),
                exact_on_true: true,
            },
            GuardPredicate::HasMember {
                value: crate::analyzer::semantic::ValueId::new(0),
                member: crate::analyzer::semantic::ValueId::new(1),
            },
            GuardPredicate::Truthy {
                value: crate::analyzer::semantic::ValueId::new(0),
            },
            GuardPredicate::Opaque {
                digest: crate::analyzer::semantic::GuardConditionDigest::from_syntax_kind("x"),
            },
        ];
        assert_eq!(samples.len(), GuardPredicate::LABELS.len());
        for sample in samples {
            let code = usize::try_from(GuardPredicateTag::of(&sample).code()).unwrap();
            assert_eq!(GuardPredicate::LABELS[code], sample.label());
        }
    }
}
