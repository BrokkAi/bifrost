// Preserve explicit engine visibility when an overlay shadows a public glob.
#![allow(hidden_glob_reexports)]

//! Language-neutral value, dispatch, and heap-oracle contracts.
//!
//! Oracle answers deliberately separate three independent questions: whether
//! an individual candidate is proven, whether the returned candidate set is
//! closed, and whether an abstract object denotes one runtime object.  A
//! proven candidate in an open set is not a must-answer, and an allocation
//! site is not automatically a singleton object.

pub use brokk_bifrost_semantic::analyzer::semantic::oracle::*;
#[doc(hidden)]
pub mod dispatch;
#[doc(hidden)]
pub mod traits;
pub use dispatch::*;
pub use traits::*;

pub(crate) mod retained;
