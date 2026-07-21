//! Language-neutral executable semantics and adapter contracts.

macro_rules! count_idents {
    ($($value:ident),* $(,)?) => {
        <[()]>::len(&[$(count_idents!(@unit $value)),*])
    };
    (@unit $value:ident) => { () };
}

pub mod capabilities;
pub(crate) mod cfg;
pub mod icfg;
pub mod ids;
pub mod ir;
pub(crate) mod lowering;
pub mod oracle;
pub mod provider;
pub mod render;
pub(crate) mod service;
pub(crate) mod workspace_oracle;

pub use crate::cancellation::CancellationToken;
pub use capabilities::*;
pub use icfg::*;
pub use ids::*;
pub use ir::*;
pub(crate) use lowering::*;
pub use oracle::*;
pub use provider::*;
pub use render::*;
pub use workspace_oracle::*;
