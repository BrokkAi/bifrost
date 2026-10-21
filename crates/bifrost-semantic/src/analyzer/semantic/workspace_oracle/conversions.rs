//! Exact bridge from shared call conversion proofs to semantic call bindings.

use crate::analyzer::semantic::ValueTransfer;

use crate::analyzer::semantic::call_conversion::ConversionUnknown;

use brokk_bifrost_core::analyzer::model::Range;

#[derive(Clone)]
#[doc(hidden)]
pub struct ArgumentConversion {
    pub range: Range,
    pub formal: usize,
    pub transfer: Result<Option<ValueTransfer>, ConversionUnknown>,
    pub incomplete_reason: Option<String>,
}
