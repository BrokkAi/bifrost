//! `KotlinAnalyzer`'s two public type-name queries.
//!
//! Kotlin's resolution ladder -- enclosing and inherited scopes, explicit
//! imports, the file's own package, star imports and the platform defaults --
//! moved to [`brokk_bifrost_jvm::kotlin::types`]. What is left is the pair of
//! `pub` methods LSP and the definition route call, plus the reach into
//! [`JvmExternalDeclarationIndex`], which imports `semantic_model` and cannot
//! cross the crate line; the crate asks it two `bool` questions through
//! `KotlinSource` instead of holding a `JvmExternalType`.

use crate::analyzer::{CodeUnit, ProjectFile};
/// The resolution ladder itself, re-exported under its historical path so the
/// definition route and the usage graph keep reading it where they always did.
pub(crate) use brokk_bifrost_jvm::kotlin::types::{
    KotlinNameScope, KotlinTypeName, resolve_kotlin_type_name,
};
use brokk_bifrost_jvm::kotlin::types::{
    kotlin_type_name_is_known_in_file, resolve_kotlin_type_name_in_file,
};

use super::KotlinAnalyzer;

impl KotlinAnalyzer {
    /// The workspace declaration a spelled type name denotes, if any.
    ///
    /// Returns `None` for a name that only exists in a dependency jar:
    /// external types are not workspace declarations and must never be
    /// fabricated as `CodeUnit`s. Use [`Self::is_known_type_name_in_file`] to
    /// ask the weaker question "does this name exist at all".
    pub fn resolve_type_name_in_file(
        &self,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        resolve_kotlin_type_name_in_file(self, file, raw_name)
    }

    /// Whether a spelled type name resolves to anything the analyzer knows:
    /// a workspace declaration or a type from the shared JVM dependency realm.
    pub fn is_known_type_name_in_file(&self, file: &ProjectFile, raw_name: &str) -> bool {
        kotlin_type_name_is_known_in_file(self, file, raw_name)
    }
}
