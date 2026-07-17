//! Language-neutral executable semantics and adapter contracts.

macro_rules! count_idents {
    ($($value:ident),* $(,)?) => {
        <[()]>::len(&[$(count_idents!(@unit $value)),*])
    };
    (@unit $value:ident) => { () };
}

pub mod capabilities;
pub(crate) mod cfg;
pub mod ids;
pub mod ir;
pub mod provider;
pub mod render;
pub(crate) mod service;

pub use crate::cancellation::CancellationToken;
pub use capabilities::*;
pub use ids::*;
pub use ir::*;
pub use provider::*;
pub use render::*;
