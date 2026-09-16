//! Content-local Java source syntax captured by the primary producer.
//!
//! These rows retain the source properties needed by Java declaration readers
//! without retaining parser handles or asking a consumer to interpret a
//! rendered signature. Type syntax is held in one arena so generic and array
//! edges remain explicit and can be traversed without recursion.

use crate::analyzer::dense_id::define_dense_id;
use crate::analyzer::model::StructuredTypeName;
use crate::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
use crate::hash::HashSet;

pub const JAVA_SOURCE_FACTS_VERSION: i64 = 1;

define_dense_id! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct JavaSourceTypeId {
        new: pub,
        get: pub,
        index: pub,
        try_from_index: pub,
    }
}

/// Flat source shape for one Java type syntax occurrence. Child IDs always
/// refer to earlier entries in `JavaSourceFacts::types`, so an incomplete
/// generic still retains its usable base without inventing a fake type name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JavaTypeSyntaxShape {
    Named {
        name: StructuredTypeName,
        parameter: Option<SourceDeclarationId>,
    },
    Generic {
        base: JavaSourceTypeId,
        arguments: Vec<JavaSourceTypeId>,
    },
    Array {
        element: JavaSourceTypeId,
        dimensions: u32,
    },
    Annotated(JavaSourceTypeId),
    NonNominal,
    Unknown,
}

/// One parser-derived Java type syntax occurrence. Native lowering and
/// declaration readers project the same shape without reparsing declarations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaTypeSyntaxFact {
    pub occurrence: SourceOccurrenceId,
    pub shape: JavaTypeSyntaxShape,
}

/// One type parameter written by a class-like or callable declaration.
/// Bounds are ordered as written (`T extends A & B`). An empty list is a
/// proven implicit `java.lang.Object` bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaTypeParameterFact {
    pub owner: SourceDeclarationId,
    pub ordinal: u32,
    pub declaration: SourceDeclarationId,
    pub name: String,
    pub bounds: Vec<JavaSourceTypeId>,
}

/// The captured declared result of one callable. Missing return syntax, as in
/// constructors, has no type entry; unsupported syntax has an explicit shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JavaCallableReturnFact {
    pub callable: SourceDeclarationId,
    pub ty: Option<JavaSourceTypeId>,
}

/// A local class's exact nearest Java lexical scope. The declaration and scope
/// extents are materialized from these source occurrences, not copied ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JavaLocalTypeFact {
    pub declaration: SourceDeclarationId,
    pub lexical_scope: SourceOccurrenceId,
}

/// The old graph behavior only has a precise positive result when every
/// observed return is an anonymous object creation with a resolvable declared
/// nominal type. Every other case remains unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaAnonymousReturnStatus {
    AllAnonymous,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JavaAnonymousReturnEntry {
    pub return_occurrence: SourceOccurrenceId,
    pub object_creation_occurrence: SourceOccurrenceId,
    pub declared_type: JavaSourceTypeId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaAnonymousReturnFact {
    pub callable: SourceDeclarationId,
    pub status: JavaAnonymousReturnStatus,
    pub returns: Vec<JavaAnonymousReturnEntry>,
}

/// The complete Java source-property family produced by one primary parse.
/// `None` on `ParsedSourceFacts` means the family was not published; this value
/// is authoritative even when every vector is empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JavaSourceFacts {
    pub types: Vec<JavaTypeSyntaxFact>,
    pub type_parameters: Vec<JavaTypeParameterFact>,
    pub callable_returns: Vec<JavaCallableReturnFact>,
    pub local_types: Vec<JavaLocalTypeFact>,
    pub anonymous_returns: Vec<JavaAnonymousReturnFact>,
    /// `(declaration, written owner declaration)`. Synthetic bodies have no
    /// source declaration and therefore never manufacture an owner pair.
    pub declaration_owners: Vec<(SourceDeclarationId, SourceDeclarationId)>,
}

impl JavaSourceFacts {
    pub fn estimated_retained_bytes(&self) -> usize {
        let mut bytes = self
            .types
            .capacity()
            .saturating_mul(std::mem::size_of::<JavaTypeSyntaxFact>())
            .saturating_add(
                self.type_parameters
                    .capacity()
                    .saturating_mul(std::mem::size_of::<JavaTypeParameterFact>()),
            )
            .saturating_add(
                self.callable_returns
                    .capacity()
                    .saturating_mul(std::mem::size_of::<JavaCallableReturnFact>()),
            )
            .saturating_add(
                self.local_types
                    .capacity()
                    .saturating_mul(std::mem::size_of::<JavaLocalTypeFact>()),
            )
            .saturating_add(
                self.anonymous_returns
                    .capacity()
                    .saturating_mul(std::mem::size_of::<JavaAnonymousReturnFact>()),
            )
            .saturating_add(self.declaration_owners.capacity().saturating_mul(
                std::mem::size_of::<(SourceDeclarationId, SourceDeclarationId)>(),
            ));
        for ty in &self.types {
            bytes = bytes.saturating_add(match &ty.shape {
                JavaTypeSyntaxShape::Named { name, .. } => name.estimated_retained_bytes(),
                JavaTypeSyntaxShape::Generic { arguments, .. } => arguments
                    .capacity()
                    .saturating_mul(std::mem::size_of::<JavaSourceTypeId>()),
                _ => 0,
            });
        }
        for parameter in &self.type_parameters {
            bytes = bytes
                .saturating_add(parameter.name.capacity())
                .saturating_add(
                    parameter
                        .bounds
                        .capacity()
                        .saturating_mul(std::mem::size_of::<JavaSourceTypeId>()),
                );
        }
        for fact in &self.anonymous_returns {
            bytes = bytes.saturating_add(
                fact.returns
                    .capacity()
                    .saturating_mul(std::mem::size_of::<JavaAnonymousReturnEntry>()),
            );
        }
        bytes
    }

    /// Check every arena edge and source handle before a store or reader uses
    /// the family. This is intentionally a total predicate so loaders can
    /// report malformed persisted rows instead of panicking while indexing.
    pub fn valid_links(&self, source: &crate::analyzer::source_facts::SourceFactRows) -> bool {
        let valid_occurrence = |id: SourceOccurrenceId| id.index() < source.occurrence_count();
        let valid_declaration = |id: SourceDeclarationId| id.index() < source.declaration_count();
        let valid_type = |id: JavaSourceTypeId| id.index() < self.types.len();
        let contains_occurrence = |outer: SourceOccurrenceId, inner: SourceOccurrenceId| {
            let outer = source.occurrence(outer).range;
            let inner = source.occurrence(inner).range;
            outer.start_byte <= inner.start_byte && inner.end_byte <= outer.end_byte
        };
        let mut type_occurrences = HashSet::default();

        for (index, ty) in self.types.iter().enumerate() {
            if !valid_occurrence(ty.occurrence) || !type_occurrences.insert(ty.occurrence) {
                return false;
            }
            match &ty.shape {
                JavaTypeSyntaxShape::Named { name, parameter } => {
                    if let Some(parameter) = parameter {
                        let Some(parameter_fact) = self
                            .type_parameters
                            .iter()
                            .find(|fact| fact.declaration == *parameter)
                        else {
                            return false;
                        };
                        if !valid_declaration(*parameter)
                            || name.is_absolute()
                            || name.path().len() != 1
                            || name.path()[0] != parameter_fact.name.as_str()
                        {
                            return false;
                        }
                    }
                }
                JavaTypeSyntaxShape::Generic { base, arguments } => {
                    if base.index() >= index
                        || arguments.iter().any(|id| id.index() >= index)
                        || !contains_occurrence(ty.occurrence, self.types[base.index()].occurrence)
                        || arguments.iter().any(|id| {
                            !contains_occurrence(ty.occurrence, self.types[id.index()].occurrence)
                        })
                    {
                        return false;
                    }
                }
                JavaTypeSyntaxShape::Array {
                    element: inner,
                    dimensions,
                } => {
                    if *dimensions == 0
                        || inner.index() >= index
                        || !contains_occurrence(ty.occurrence, self.types[inner.index()].occurrence)
                    {
                        return false;
                    }
                }
                JavaTypeSyntaxShape::Annotated(inner) => {
                    if inner.index() >= index
                        || !contains_occurrence(ty.occurrence, self.types[inner.index()].occurrence)
                    {
                        return false;
                    }
                }
                JavaTypeSyntaxShape::NonNominal | JavaTypeSyntaxShape::Unknown => {}
            }
        }
        let mut complete = Vec::with_capacity(self.types.len());
        for fact in &self.types {
            let value = match &fact.shape {
                JavaTypeSyntaxShape::Named { .. } => true,
                JavaTypeSyntaxShape::Generic { base, arguments } => {
                    complete[base.index()] && arguments.iter().all(|id| complete[id.index()])
                }
                JavaTypeSyntaxShape::Array {
                    element,
                    dimensions,
                } => *dimensions > 0 && complete[element.index()],
                JavaTypeSyntaxShape::Annotated(inner) => complete[inner.index()],
                JavaTypeSyntaxShape::NonNominal | JavaTypeSyntaxShape::Unknown => false,
            };
            complete.push(value);
        }
        let mut parameter_declarations = HashSet::default();
        let mut parameter_ordinals = HashSet::default();
        for parameter in &self.type_parameters {
            if !valid_declaration(parameter.owner) || !valid_declaration(parameter.declaration) {
                return false;
            }
            if source.declaration(parameter.declaration).name.is_none() || parameter.name.is_empty()
            {
                return false;
            }
            if !parameter_declarations.insert(parameter.declaration)
                || !parameter_ordinals.insert((parameter.owner, parameter.ordinal))
            {
                return false;
            }
            if parameter.bounds.iter().any(|id| {
                !valid_type(*id)
                    || !contains_occurrence(
                        source.declaration(parameter.declaration).occurrence,
                        self.types[id.index()].occurrence,
                    )
            }) {
                return false;
            }
        }
        for callable in &self.callable_returns {
            if !valid_declaration(callable.callable)
                || callable.ty.is_some_and(|id| !valid_type(id))
                || callable.ty.is_some_and(|id| {
                    !contains_occurrence(
                        source.declaration(callable.callable).occurrence,
                        self.types[id.index()].occurrence,
                    )
                })
            {
                return false;
            }
        }
        for local in &self.local_types {
            if !valid_declaration(local.declaration) || !valid_occurrence(local.lexical_scope) {
                return false;
            }
            if !contains_occurrence(
                local.lexical_scope,
                source.declaration(local.declaration).occurrence,
            ) {
                return false;
            }
        }
        for anonymous in &self.anonymous_returns {
            if !valid_declaration(anonymous.callable) {
                return false;
            }
            if matches!(anonymous.status, JavaAnonymousReturnStatus::AllAnonymous)
                && anonymous.returns.is_empty()
            {
                return false;
            }
            if matches!(anonymous.status, JavaAnonymousReturnStatus::Unknown)
                && !anonymous.returns.is_empty()
            {
                return false;
            }
            if anonymous.returns.iter().any(|entry| {
                !valid_occurrence(entry.return_occurrence)
                    || !valid_occurrence(entry.object_creation_occurrence)
                    || !valid_type(entry.declared_type)
                    || !complete[entry.declared_type.index()]
                    || !contains_occurrence(
                        entry.return_occurrence,
                        entry.object_creation_occurrence,
                    )
                    || !contains_occurrence(
                        entry.object_creation_occurrence,
                        self.types[entry.declared_type.index()].occurrence,
                    )
            }) {
                return false;
            }
        }
        let mut owner_declarations = HashSet::default();
        self.declaration_owners.iter().all(|(declaration, owner)| {
            valid_declaration(*declaration)
                && valid_declaration(*owner)
                && owner.index() < declaration.index()
                && contains_occurrence(
                    source.declaration(*owner).occurrence,
                    source.declaration(*declaration).occurrence,
                )
                && owner_declarations.insert(*declaration)
        })
    }
}

/// Source-proven implicit construction shape, before workspace selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaTypeConstructorShape {
    NoImplicit,
    Default,
    RecordCanonical(crate::analyzer::model::CallableArity),
}
