//! Code Semantic Model Interchange (CSMI) v0.1 import, export, and validation.
//!
//! The wire model is deliberately separate from Bifrost's authored and
//! compiled semantic-pack types. Conversion happens only through the explicit
//! import and export adapters in this module.

mod canonical;
mod cpp;
mod deferred_yield;
mod export;
mod identity;
mod import;
mod model;
mod pack;
pub(crate) mod python;
mod runtime_contract_validation;
mod validate;
mod value_transfer;

#[cfg(test)]
pub(crate) mod tests;

pub use canonical::*;
pub use export::*;
pub use identity::*;
pub use import::*;
pub use model::*;
pub use pack::*;
pub(crate) use python::validate_python_artifact;
pub use python::{CsmiShapeAuthoringError, author_python_callable_shape_evidence};
pub(crate) use runtime_contract_validation::validate_runtime_contract_semantics;
pub(crate) use validate::validate_python_profile_condition;
pub use validate::*;

pub(crate) fn entry_parameter_projection(position: u32) -> CsmiProjection {
    CsmiProjection {
        scheme: CSMI_COLLECTION_FLOW_PROFILE_ID.to_owned(),
        scheme_version: CSMI_COLLECTION_FLOW_PROFILE_VERSION.to_owned(),
        steps: vec![CsmiProjectionStep {
            kind: "entry".to_owned(),
            args: Some(serde_json::json!({
                "key": {"kind": "parameter", "position": position}
            })),
        }],
    }
}

pub(crate) fn collection_value_shape(symbol: &str) -> CsmiCollectionFlowShape {
    CsmiCollectionFlowShape::Value {
        r#type: CsmiTypeExpression::Parameter(CsmiParameterType {
            kind: CsmiParameterTypeKind::Parameter,
            symbol: symbol.to_owned(),
        }),
    }
}
