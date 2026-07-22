//! Language-neutral value, dispatch, and heap-oracle contracts.
//!
//! Oracle answers deliberately separate three independent questions: whether
//! an individual candidate is proven, whether the returned candidate set is
//! closed, and whether an abstract object denotes one runtime object.  A
//! proven candidate in an open set is not a must-answer, and an allocation
//! site is not automatically a singleton object.

mod call;
mod dispatch;
mod error;
mod heap;
mod limits;
mod model;
mod relation;
mod traits;
mod value_flow;

pub use call::*;
pub use dispatch::*;
pub use error::*;
pub use heap::*;
pub use limits::*;
pub use model::*;
pub use relation::*;
pub use traits::*;
pub use value_flow::*;
