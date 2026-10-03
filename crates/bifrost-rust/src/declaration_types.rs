//! Indexed declaration annotations over one selected canonical source product.
//!
//! These indexes do not resolve types or retain parser nodes. Every position
//! addresses the same immutable fact product, including all mounted CodeUnit
//! alternatives for repeated source declarations.

use crate::graph_support::RustCargoRouteError;
use crate::hierarchy::RustHierarchySourceFacts;
use crate::hierarchy_source_context::RustSourceContextIndex;
use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::rust_facts::{
    RustGenericParameterSourceFact, RustImplSourceFact, RustSourceContextKind, RustTypeSourceFact,
};
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
use brokk_bifrost_core::hash::HashMap;
use std::sync::Arc;

#[derive(Clone, Copy)]
enum AnnotationRow {
    Value(usize),
    Callable(usize),
    Alias(usize),
}

#[cfg(test)]
#[path = "declaration_types_tests.rs"]
mod tests;

/// The annotation and containing context belonging to one exact declaration.
#[derive(Clone, Copy, Debug)]
pub struct RustSourceAnnotation {
    pub declaration: SourceDeclarationId,
    pub context: SourceOccurrenceId,
    pub type_occurrence: Option<SourceOccurrenceId>,
}

/// The canonical lexical scopes containing a primary Rust declaration.
///
/// `local_scope` is the nearest block, function, impl, trait, or module
/// context. A declaration directly under a file root has no local scope.
/// `module` is the nearest module context, if any. Embedded declarations are
/// intentionally excluded from this projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RustDeclarationScope {
    pub local_scope: Option<SourceOccurrenceId>,
    pub module: Option<SourceOccurrenceId>,
}

pub struct RustDeclarationTypeIndex {
    facts: Arc<RustHierarchySourceFacts>,
    pub contexts: RustSourceContextIndex,
    declarations: RustSourceDeclarationIndex,
    annotations: HashMap<SourceDeclarationId, AnnotationRow>,
    types: HashMap<SourceOccurrenceId, usize>,
    generics: HashMap<SourceDeclarationId, usize>,
    impls: HashMap<SourceDeclarationId, usize>,
    macro_definitions: HashMap<SourceDeclarationId, usize>,
}

/// Exact mounted declaration links, shared by annotation and macro readers.
pub struct RustSourceDeclarationIndex {
    declarations: HashMap<CodeUnit, Vec<SourceDeclarationId>>,
    units: HashMap<SourceDeclarationId, Vec<usize>>,
}

impl RustSourceDeclarationIndex {
    pub fn new(
        facts: &RustHierarchySourceFacts,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Self, RustCargoRouteError> {
        let mut index = Self {
            declarations: HashMap::default(),
            units: HashMap::default(),
        };
        for (position, (declaration, unit)) in facts.declaration_units.iter().enumerate() {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            index
                .declarations
                .entry(unit.clone())
                .or_default()
                .push(*declaration);
            index.units.entry(*declaration).or_default().push(position);
        }
        Ok(index)
    }

    pub fn declarations_for(&self, unit: &CodeUnit) -> &[SourceDeclarationId] {
        self.declarations.get(unit).map_or(&[], Vec::as_slice)
    }

    pub fn units_for<'a>(
        &'a self,
        facts: &'a RustHierarchySourceFacts,
        declaration: SourceDeclarationId,
    ) -> impl Iterator<Item = &'a CodeUnit> {
        self.units
            .get(&declaration)
            .into_iter()
            .flatten()
            .map(|position| &facts.declaration_units[*position].1)
    }
}

impl RustDeclarationTypeIndex {
    pub fn new(
        facts: Arc<RustHierarchySourceFacts>,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Self, RustCargoRouteError> {
        let contexts = RustSourceContextIndex::new(&facts, keep_going)?;
        let declarations = RustSourceDeclarationIndex::new(&facts, keep_going)?;
        let mut index = Self {
            facts,
            contexts,
            declarations,
            annotations: HashMap::default(),
            types: HashMap::default(),
            generics: HashMap::default(),
            impls: HashMap::default(),
            macro_definitions: HashMap::default(),
        };
        for (declaration, row) in index
            .facts
            .items
            .values
            .iter()
            .enumerate()
            .map(|(position, row)| (row.declaration, AnnotationRow::Value(position)))
            .chain(
                index
                    .facts
                    .items
                    .callables
                    .iter()
                    .enumerate()
                    .map(|(position, row)| (row.declaration, AnnotationRow::Callable(position))),
            )
            .chain(
                index
                    .facts
                    .items
                    .aliases
                    .iter()
                    .enumerate()
                    .map(|(position, row)| (row.declaration, AnnotationRow::Alias(position))),
            )
        {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            assert!(
                index.annotations.insert(declaration, row).is_none(),
                "one source declaration has one annotation family"
            );
        }
        for (position, ty) in index.facts.types.iter().enumerate() {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            assert!(
                index.types.insert(ty.occurrence, position).is_none(),
                "one source occurrence has one type fact"
            );
        }
        for (position, group) in index.facts.items.generics.iter().enumerate() {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            assert!(
                index.generics.insert(group.declaration, position).is_none(),
                "one source declaration has one generic group"
            );
        }
        for (position, implementation) in index.facts.items.impls.iter().enumerate() {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            assert!(
                index
                    .impls
                    .insert(implementation.declaration, position)
                    .is_none(),
                "one source declaration has one impl fact"
            );
        }
        for (position, macro_definition) in index.facts.items.macro_definitions.iter().enumerate() {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            assert!(
                index
                    .macro_definitions
                    .insert(macro_definition.declaration, position)
                    .is_none(),
                "one source declaration has one macro definition fact"
            );
        }
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        Ok(index)
    }

    pub fn facts(&self) -> &Arc<RustHierarchySourceFacts> {
        &self.facts
    }

    pub fn declarations_for(&self, unit: &CodeUnit) -> &[SourceDeclarationId] {
        self.declarations.declarations_for(unit)
    }

    pub fn units_for(&self, declaration: SourceDeclarationId) -> impl Iterator<Item = &CodeUnit> {
        self.declarations.units_for(&self.facts, declaration)
    }

    pub fn annotation(&self, declaration: SourceDeclarationId) -> Option<RustSourceAnnotation> {
        let (context, type_occurrence) = match *self.annotations.get(&declaration)? {
            AnnotationRow::Value(position) => {
                let row = &self.facts.items.values[position];
                (row.context, row.declared_type)
            }
            AnnotationRow::Callable(position) => {
                let row = &self.facts.items.callables[position];
                (row.context, row.return_type)
            }
            AnnotationRow::Alias(position) => {
                let row = &self.facts.items.aliases[position];
                (row.context, row.target_type)
            }
        };
        Some(RustSourceAnnotation {
            declaration,
            context,
            type_occurrence,
        })
    }

    pub fn is_alias(&self, declaration: SourceDeclarationId) -> bool {
        matches!(
            self.annotations.get(&declaration),
            Some(AnnotationRow::Alias(_))
        )
    }

    pub fn type_fact(&self, occurrence: SourceOccurrenceId) -> &RustTypeSourceFact {
        &self.facts.types[*self
            .types
            .get(&occurrence)
            .expect("published annotation and generic type links have type facts")]
    }

    pub fn generic_parameters(
        &self,
        declaration: SourceDeclarationId,
    ) -> &[RustGenericParameterSourceFact] {
        self.generics.get(&declaration).map_or(&[], |position| {
            self.facts.items.generics[*position].parameters.as_slice()
        })
    }

    pub fn impl_fact(&self, declaration: SourceDeclarationId) -> Option<&RustImplSourceFact> {
        self.impls
            .get(&declaration)
            .map(|position| &self.facts.items.impls[*position])
    }

    /// Project the lexical scope of one canonical declaration.
    ///
    /// Owned Function, Type, Trait, and Module contexts begin at their parent
    /// so the declaration's own body cannot become its local scope. Values
    /// use their exact annotation context, and macros use their captured
    /// containing context. The remaining context chain is walked iteratively,
    /// preserving the nearest relevant context and module without consulting
    /// parser nodes or source ranges.
    pub fn declaration_scope(
        &self,
        declaration: SourceDeclarationId,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<RustDeclarationScope>, RustCargoRouteError> {
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let context =
            if let Some(AnnotationRow::Value(position)) = self.annotations.get(&declaration) {
                self.facts.items.values[*position].context
            } else if let Some(position) = self.macro_definitions.get(&declaration).copied() {
                self.facts.items.macro_definitions[position].context
            } else {
                let owned_context = self
                    .contexts
                    .owner_context(declaration)
                    .ok_or(RustCargoRouteError::Unavailable)?;
                let owned = self.contexts.context(&self.facts, owned_context)?;
                if !matches!(
                    owned.kind,
                    RustSourceContextKind::Function
                        | RustSourceContextKind::Type
                        | RustSourceContextKind::Trait
                        | RustSourceContextKind::Module
                ) {
                    return Err(RustCargoRouteError::Unavailable);
                }
                owned.parent.ok_or(RustCargoRouteError::Unavailable)?
            };
        if !self.contexts.is_primary(&self.facts, context)? {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            return Ok(None);
        }

        let mut scope = RustDeclarationScope {
            local_scope: None,
            module: None,
        };
        let mut current = context;
        loop {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            let row = self.contexts.context(&self.facts, current)?;
            match row.kind {
                RustSourceContextKind::Block
                | RustSourceContextKind::Function
                | RustSourceContextKind::Impl
                | RustSourceContextKind::Trait
                | RustSourceContextKind::Module => {
                    if scope.local_scope.is_none() {
                        scope.local_scope = Some(row.context);
                    }
                    if row.kind == RustSourceContextKind::Module && scope.module.is_none() {
                        scope.module = Some(row.context);
                    }
                }
                RustSourceContextKind::FileRoot => break,
                RustSourceContextKind::DeclarationBody | RustSourceContextKind::Type => {}
            }
            current = row.parent.ok_or(RustCargoRouteError::Unavailable)?;
        }
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        Ok(Some(scope))
    }
}
