//! Language-neutral value, dispatch, and heap-oracle contracts.
//!
//! Oracle answers deliberately separate three independent questions: whether
//! an individual candidate is proven, whether the returned candidate set is
//! closed, and whether an abstract object denotes one runtime object.  A
//! proven candidate in an open set is not a must-answer, and an allocation
//! site is not automatically a singleton object.

#[doc(hidden)]
pub mod call;
#[doc(hidden)]
pub mod dispatch;
#[doc(hidden)]
pub mod error;
#[doc(hidden)]
pub mod heap;
#[doc(hidden)]
pub mod limits;
#[doc(hidden)]
pub mod model;
#[doc(hidden)]
pub mod relation;
#[doc(hidden)]
pub mod retained;
#[doc(hidden)]
pub mod traits;
#[doc(hidden)]
pub mod value_flow;

pub use crate::analyzer::semantic::oracle::call::*;

pub use crate::analyzer::semantic::oracle::dispatch::*;

pub use crate::analyzer::semantic::oracle::error::*;

pub use crate::analyzer::semantic::oracle::heap::*;

pub use crate::analyzer::semantic::oracle::limits::*;

pub use crate::analyzer::semantic::oracle::model::*;

pub use crate::analyzer::semantic::oracle::relation::*;

pub use crate::analyzer::semantic::oracle::traits::*;

pub use crate::analyzer::semantic::oracle::value_flow::*;
