//! Local adapter for persisted engine hierarchy rows.

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::HierarchyDeclarationFacts;
use brokk_bifrost_core::analyzer::model::{CodeUnit, ImportInfo, Range};

#[repr(transparent)]
#[derive(Clone)]
pub(crate) struct JvmHierarchyFact(pub(crate) HierarchyDeclarationFacts);

impl AsRef<HierarchyDeclarationFacts> for JvmHierarchyFact {
    fn as_ref(&self) -> &HierarchyDeclarationFacts {
        &self.0
    }
}

impl AsMut<HierarchyDeclarationFacts> for JvmHierarchyFact {
    fn as_mut(&mut self) -> &mut HierarchyDeclarationFacts {
        &mut self.0
    }
}

impl brokk_bifrost_jvm::java::hierarchy::JavaHierarchyFact for JvmHierarchyFact {
    fn declaration(&self) -> &CodeUnit {
        &self.0.declaration
    }

    fn primary_range(&self) -> Option<&Range> {
        self.0.primary_range()
    }

    fn imports(&self) -> &[ImportInfo] {
        &self.0.imports
    }

    fn raw_supertypes(&self) -> &[String] {
        &self.0.raw_supertypes
    }
}

impl brokk_bifrost_jvm::kotlin::hierarchy::KotlinHierarchyFact for JvmHierarchyFact {
    fn declaration(&self) -> &CodeUnit {
        &self.0.declaration
    }

    fn primary_range(&self) -> Option<Range> {
        self.0.primary_range().copied()
    }

    fn imports(&self) -> &[ImportInfo] {
        &self.0.imports
    }

    fn raw_supertypes(&self) -> &[String] {
        &self.0.raw_supertypes
    }
}
