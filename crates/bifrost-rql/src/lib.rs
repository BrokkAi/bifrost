//! RQL syntax, typed IR, planning, execution, and result contracts.

extern crate self as brokk_bifrost_rql;

pub mod query;
pub mod refs;
pub mod sexp;
pub mod structural;

pub use brokk_bifrost_analysis::{analyzer, path_utils, profiling};
pub use brokk_bifrost_core::{cancellation, hash, text_utils};

pub use query::*;
pub use refs::{
    MAX_PROTOCOL_NAME_BYTES, MAX_PROTOCOL_NAMESPACE_BYTES, MAX_PROTOCOL_REF_BYTES,
    MAX_TAINT_RESULT_NAME_BYTES, MAX_TAINT_RESULT_NAMESPACE_BYTES, MAX_TAINT_RESULT_REF_BYTES,
    MAX_VALUE_FLOW_PLAN_NAME_BYTES, MAX_VALUE_FLOW_PLAN_NAMESPACE_BYTES,
    MAX_VALUE_FLOW_PLAN_REF_BYTES, ProtocolNameError, ProtocolNamespaceError, ProtocolRef,
    ProtocolRefError, TaintResultNameError, TaintResultNamespaceError, TaintResultRef,
    TaintResultRefError, ValueFlowPlanNameError, ValueFlowPlanNamespaceError, ValueFlowPlanRef,
    ValueFlowPlanRefError,
};
pub use structural::*;
