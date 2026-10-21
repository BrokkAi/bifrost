//! Code Semantic Model Interchange (CSMI) v0.1 import, export, and validation.
//!
//! The wire model is deliberately separate from Bifrost's authored and
//! compiled semantic-pack types. Conversion happens only through the explicit
//! import and export adapters in this module.

#[doc(hidden)]
pub mod canonical;
mod cpp;
mod deferred_yield;
#[doc(hidden)]
pub mod export;
#[doc(hidden)]
pub mod identity;
#[doc(hidden)]
pub mod import;
#[doc(hidden)]
pub mod model;
#[doc(hidden)]
pub mod pack;
#[doc(hidden)]
pub mod python;
#[doc(hidden)]
pub mod runtime_contract_validation;
#[doc(hidden)]
pub mod validate;
mod value_transfer;

pub use crate::analyzer::semantic_model::csmi::canonical::*;

pub use crate::analyzer::semantic_model::csmi::export::*;

pub use crate::analyzer::semantic_model::csmi::identity::*;

pub use crate::analyzer::semantic_model::csmi::import::*;

pub use crate::analyzer::semantic_model::csmi::model::*;

pub use crate::analyzer::semantic_model::csmi::pack::*;

pub(crate) use crate::analyzer::semantic_model::csmi::python::validate_python_artifact;

pub use crate::analyzer::semantic_model::csmi::python::CsmiShapeAuthoringError;

pub use crate::analyzer::semantic_model::csmi::python::author_python_callable_shape_evidence;

pub(crate) use crate::analyzer::semantic_model::csmi::runtime_contract_validation::validate_runtime_contract_semantics;

pub(crate) use crate::analyzer::semantic_model::csmi::validate::validate_python_profile_condition;

pub use crate::analyzer::semantic_model::csmi::validate::*;

#[doc(hidden)]
pub fn entry_parameter_projection(position: u32) -> CsmiProjection {
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

#[doc(hidden)]
pub fn collection_value_shape(symbol: &str) -> CsmiCollectionFlowShape {
    CsmiCollectionFlowShape::Value {
        r#type: CsmiTypeExpression::Parameter(CsmiParameterType {
            kind: CsmiParameterTypeKind::Parameter,
            symbol: symbol.to_owned(),
        }),
    }
}
