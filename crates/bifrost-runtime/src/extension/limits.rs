use crate::CancellationToken;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionLimitValues {
    pub result_items: u32,
    pub result_bytes: u64,
    pub diagnostics: u32,
    pub source_bytes: u64,
    pub semantic_nodes: u32,
    pub semantic_edges: u32,
    pub semantic_files: u32,
    pub traversal_steps: u64,
    pub call_depth: u16,
}
impl Default for ExtensionLimitValues {
    fn default() -> Self {
        Self {
            result_items: 1_000,
            result_bytes: 8 << 20,
            diagnostics: 256,
            source_bytes: 16 << 20,
            semantic_nodes: 10_000,
            semantic_edges: 20_000,
            semantic_files: 128,
            traversal_steps: 1_000_000,
            call_depth: 8,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtensionLimits(ExtensionLimitValues);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidExtensionLimits(&'static str);
impl fmt::Display for InvalidExtensionLimits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for InvalidExtensionLimits {}
impl ExtensionLimits {
    pub fn new(values: ExtensionLimitValues) -> Result<Self, InvalidExtensionLimits> {
        if values.result_items == 0
            || values.result_bytes == 0
            || values.diagnostics == 0
            || values.source_bytes == 0
            || values.semantic_nodes == 0
            || values.semantic_edges == 0
            || values.semantic_files == 0
            || values.traversal_steps == 0
            || values.call_depth == 0
        {
            return Err(InvalidExtensionLimits(
                "every extension limit must be positive",
            ));
        }
        Ok(Self(values))
    }
    pub const fn values(&self) -> ExtensionLimitValues {
        self.0
    }
}
impl Serialize for ExtensionLimits {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for ExtensionLimits {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(ExtensionLimitValues::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExtensionCancellation(CancellationToken);
impl ExtensionCancellation {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.cancel();
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
    pub(crate) fn token(&self) -> &CancellationToken {
        &self.0
    }
}
