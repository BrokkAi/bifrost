//! Content-local Go declaration syntax captured by the primary producer.
//!
//! These records describe written types, not resolved workspace names. Arena
//! edges point to earlier entries, so storage validation and consumers never
//! need recursive traversal. Presentation text is retained only where existing
//! method-set comparison treats an AST construct as opaque syntax.

use crate::analyzer::dense_id::define_dense_id;
use crate::analyzer::model::StructuredTypeName;
use crate::analyzer::source_facts::{SourceDeclarationId, SourceFactRows, SourceOccurrenceId};

pub const GO_SOURCE_FACTS_VERSION: i64 = 1;

/// Version of the supplemental Go build-selection fact stored with the source
/// manifest. Older cache rows remain explicitly unknown until republished.
pub const GO_BUILD_SELECTION_FACTS_VERSION: i64 = 1;

define_dense_id! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct GoSourceTypeId {
        new: pub,
        get: pub,
        index: pub,
        try_from_index: pub,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoChannelDirection {
    Both,
    Receive,
    Send,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoTypeCompoundKind {
    Parenthesized,
    Element,
    Constraint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoSourceTypeShape {
    Named(StructuredTypeName),
    Pointer(GoSourceTypeId),
    Slice(GoSourceTypeId),
    Array {
        element: GoSourceTypeId,
        length: SourceOccurrenceId,
        length_text: String,
    },
    ImplicitArray {
        element: GoSourceTypeId,
        /// Present only when this syntax was required by MethodKey
        /// comparison. `None` is unavailable/not demanded, not an empty
        /// spelling sentinel.
        text: Option<String>,
    },
    Map {
        key: GoSourceTypeId,
        value: GoSourceTypeId,
    },
    Channel {
        direction: GoChannelDirection,
        element: GoSourceTypeId,
    },
    Generic {
        base: GoSourceTypeId,
        arguments: Vec<GoSourceTypeId>,
        argument_list: SourceOccurrenceId,
        /// Existing Go MethodKey comparison keeps this list's exact spelling.
        /// It is retained only when that comparison demands it. Structured
        /// identity consumers use `arguments`, never parse this text.
        argument_text: Option<String>,
    },
    Compound {
        kind: GoTypeCompoundKind,
        children: Vec<GoSourceTypeId>,
    },
    Negated(GoSourceTypeId),
    Struct {
        /// Existing method-set comparison treats inline struct syntax as text.
        /// It is retained only when that comparison demands it.
        text: Option<String>,
    },
    Interface {
        /// Retained only when method-set comparison demands the opaque syntax.
        text: Option<String>,
        /// Includes comments, matching the former named-child emptiness test.
        has_named_children: bool,
    },
    /// Unsupported or recovered grammar remains explicit source evidence.
    Opaque {
        /// Best-effort source spelling, when the bounded source slice is
        /// available. Absence remains explicit evidence of unavailable text.
        text: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoSourceTypeFact {
    pub occurrence: SourceOccurrenceId,
    pub shape: GoSourceTypeShape,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoTypeDeclarationFact {
    pub declaration: SourceDeclarationId,
    pub name: String,
    pub ty: GoSourceTypeId,
    pub file_scope: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoAliasFact {
    pub declaration: SourceDeclarationId,
    pub name: String,
    pub target: Option<GoSourceTypeId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoFieldFact {
    pub declaration: SourceDeclarationId,
    /// Exact written struct container, shared by repeated inline projections.
    pub owner: GoSourceTypeId,
    pub ty: Option<GoSourceTypeId>,
    /// An embedded field's derived terminal name is not a written binder.
    pub name: String,
    pub embedded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoCallableParameterFact {
    pub group: SourceOccurrenceId,
    pub name: Option<SourceOccurrenceId>,
    pub ty: Option<GoSourceTypeId>,
    pub variadic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoCallableFact {
    pub declaration: SourceDeclarationId,
    pub name: String,
    /// Interface methods have a written interface container owner. Receiver
    /// methods instead resolve `receiver` in their own file's import context.
    pub owner: Option<GoSourceTypeId>,
    pub receiver: Option<GoSourceTypeId>,
    pub is_method: bool,
    /// Missing parameter syntax differs from a present, empty parameter list.
    pub parameters: Option<Vec<GoCallableParameterFact>>,
    pub results: Vec<GoCallableParameterFact>,
    pub result: Option<SourceOccurrenceId>,
    pub body: Option<SourceOccurrenceId>,
    pub file_scope: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoEmbeddingFact {
    pub owner: GoSourceTypeId,
    pub occurrence: SourceOccurrenceId,
    pub ty: GoSourceTypeId,
}

/// `Some(GoSourceFacts::default())` is an authoritative empty publication;
/// absence of this family is not evidence that the file declares nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoSourceFacts {
    pub types: Vec<GoSourceTypeFact>,
    pub declarations: Vec<GoTypeDeclarationFact>,
    pub aliases: Vec<GoAliasFact>,
    pub fields: Vec<GoFieldFact>,
    pub callables: Vec<GoCallableFact>,
    pub embeddings: Vec<GoEmbeddingFact>,
    /// Whether this source file's leading package header contains a Go build
    /// constraint comment. `None` means an older source manifest does not carry
    /// this supplemental fact, so package placement cannot be certified.
    pub has_build_constraints: Option<bool>,
    /// Digest of every input the Go tool reads to place this file in a package:
    /// the bytes through the package clause and the import declarations, which
    /// hold the build constraints, the package name and any `import "C"`. An
    /// unsaved replacement with the same digest keeps its predecessor's
    /// selected package membership. `None` when that region is malformed.
    pub membership_digest: Option<[u8; 32]>,
}

impl GoSourceFacts {
    pub fn estimated_retained_bytes(&self) -> usize {
        let mut bytes = self.types.capacity() * std::mem::size_of::<GoSourceTypeFact>()
            + self.declarations.capacity() * std::mem::size_of::<GoTypeDeclarationFact>()
            + self.aliases.capacity() * std::mem::size_of::<GoAliasFact>()
            + self.fields.capacity() * std::mem::size_of::<GoFieldFact>()
            + self.callables.capacity() * std::mem::size_of::<GoCallableFact>()
            + self.embeddings.capacity() * std::mem::size_of::<GoEmbeddingFact>();
        for ty in &self.types {
            bytes = bytes.saturating_add(match &ty.shape {
                GoSourceTypeShape::Named(name) => {
                    name.path()
                        .iter()
                        .chain(name.lexical_scope())
                        .map(String::capacity)
                        .sum::<usize>()
                        + (name.path().len() + name.lexical_scope().len())
                            * std::mem::size_of::<String>()
                }
                GoSourceTypeShape::Array { length_text, .. } => length_text.capacity(),
                GoSourceTypeShape::Generic {
                    arguments,
                    argument_text,
                    ..
                } => {
                    arguments.capacity() * std::mem::size_of::<GoSourceTypeId>()
                        + argument_text.as_ref().map_or(0, |text| text.capacity())
                }
                GoSourceTypeShape::Compound { children, .. } => {
                    children.capacity() * std::mem::size_of::<GoSourceTypeId>()
                }
                GoSourceTypeShape::ImplicitArray { text, .. }
                | GoSourceTypeShape::Struct { text }
                | GoSourceTypeShape::Interface { text, .. }
                | GoSourceTypeShape::Opaque { text } => {
                    text.as_ref().map_or(0, |text| text.capacity())
                }
                _ => 0,
            });
        }
        for name in self
            .declarations
            .iter()
            .map(|fact| &fact.name)
            .chain(self.aliases.iter().map(|fact| &fact.name))
            .chain(self.fields.iter().map(|fact| &fact.name))
            .chain(self.callables.iter().map(|fact| &fact.name))
        {
            bytes = bytes.saturating_add(name.capacity());
        }
        for callable in &self.callables {
            bytes = bytes.saturating_add(
                (callable.parameters.as_ref().map_or(0, Vec::capacity)
                    + callable.results.capacity())
                    * std::mem::size_of::<GoCallableParameterFact>(),
            );
        }
        bytes
    }

    /// Validate externally reconstructed rows before exposing arena access.
    /// Producers assert this at construction; persisted readers report invalid
    /// publication rather than turning invalid links into unknown types.
    pub fn valid_links(&self, source: &SourceFactRows) -> bool {
        let occurrence = |id: SourceOccurrenceId| id.index() < source.occurrence_count();
        let declaration = |id: SourceDeclarationId| id.index() < source.declaration_count();
        let ty = |id: GoSourceTypeId| id.index() < self.types.len();
        for (index, fact) in self.types.iter().enumerate() {
            if !occurrence(fact.occurrence) {
                return false;
            }
            let child = |id: GoSourceTypeId| id.index() < index;
            let valid = match &fact.shape {
                GoSourceTypeShape::Named(name) => {
                    name.path().len() <= 2 && name.lexical_scope().is_empty() && !name.is_absolute()
                }
                GoSourceTypeShape::Pointer(inner)
                | GoSourceTypeShape::Slice(inner)
                | GoSourceTypeShape::Negated(inner) => child(*inner),
                GoSourceTypeShape::ImplicitArray { element, text } => {
                    child(*element) && text.as_ref().is_none_or(|text| !text.is_empty())
                }
                GoSourceTypeShape::Channel { element, .. } => child(*element),
                GoSourceTypeShape::Array {
                    element,
                    length,
                    length_text,
                } => child(*element) && occurrence(*length) && !length_text.is_empty(),
                GoSourceTypeShape::Map { key, value } => child(*key) && child(*value),
                GoSourceTypeShape::Generic {
                    base,
                    arguments,
                    argument_list,
                    argument_text,
                } => {
                    child(*base)
                        && arguments.iter().copied().all(child)
                        && occurrence(*argument_list)
                        && argument_text.as_ref().is_none_or(|text| !text.is_empty())
                }
                GoSourceTypeShape::Compound { children, .. } => children.iter().copied().all(child),
                GoSourceTypeShape::Struct { text }
                | GoSourceTypeShape::Interface { text, .. }
                | GoSourceTypeShape::Opaque { text } => {
                    text.as_ref().is_none_or(|text| !text.is_empty())
                }
            };
            if !valid {
                return false;
            }
        }
        let parameter = |fact: &GoCallableParameterFact| {
            occurrence(fact.group) && fact.name.is_none_or(occurrence) && fact.ty.is_none_or(ty)
        };
        self.declarations
            .iter()
            .all(|fact| declaration(fact.declaration) && ty(fact.ty) && !fact.name.is_empty())
            && self.aliases.iter().all(|fact| {
                declaration(fact.declaration) && fact.target.is_none_or(ty) && !fact.name.is_empty()
            })
            && self.fields.iter().all(|fact| {
                declaration(fact.declaration)
                    && ty(fact.owner)
                    && fact.ty.is_none_or(ty)
                    && !fact.name.is_empty()
                    && matches!(
                        self.types[fact.owner.index()].shape,
                        GoSourceTypeShape::Struct { .. }
                    )
            })
            && self.callables.iter().all(|fact| {
                declaration(fact.declaration)
                    && !fact.name.is_empty()
                    && fact.owner.is_none_or(|owner| {
                        ty(owner)
                            && matches!(
                                self.types[owner.index()].shape,
                                GoSourceTypeShape::Interface { .. }
                            )
                    })
                    && fact.receiver.is_none_or(ty)
                    && fact.result.is_none_or(occurrence)
                    && fact.body.is_none_or(occurrence)
                    && fact
                        .parameters
                        .as_ref()
                        .is_none_or(|parameters| parameters.iter().all(parameter))
                    && fact.results.iter().all(parameter)
            })
            && self.embeddings.iter().all(|fact| {
                ty(fact.owner)
                    && ty(fact.ty)
                    && occurrence(fact.occurrence)
                    && matches!(
                        self.types[fact.owner.index()].shape,
                        GoSourceTypeShape::Struct { .. } | GoSourceTypeShape::Interface { .. }
                    )
            })
    }
}
