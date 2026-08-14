//! Analyzer-independent RQL syntax, schema, typed IR, and validation.

pub mod query;
pub mod refs;
pub mod sexp;

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
