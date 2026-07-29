use serde::{Deserialize, Serialize};

/// The kind of source location an explicit navigation request should select.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NavigationOperation {
    Declaration,
    Definition,
}
