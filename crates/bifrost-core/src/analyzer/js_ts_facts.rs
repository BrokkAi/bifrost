//! Content-owned JavaScript/TypeScript declaration and module facts.

use super::dense_id::define_dense_id;
use super::source_facts::{SourceDeclarationId, SourceImportId, SourceOccurrenceId};
use super::usages::model::ImportKind;

pub const JS_TS_SOURCE_FACTS_VERSION: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JsTsSourceFacts {
    pub file_is_external_module: bool,
    pub file_is_esm: bool,
    pub bindings: Vec<JsTsImportBindingFact>,
    pub exports: Vec<JsTsExportFact>,
    pub declarations: Vec<JsTsDeclarationFact>,
    pub types: Vec<JsTsTypeFact>,
    pub declaration_bindings: Vec<JsTsDeclarationBindingFact>,
    pub property_receivers: Vec<JsTsPropertyReceiverFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsDeclarationBindingFact {
    pub declaration: SourceDeclarationId,
    pub binder: SourceOccurrenceId,
    pub name: String,
    pub is_program: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsTsReceiverBinding {
    Unbound,
    Program,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsPropertyReceiverFact {
    pub declaration: SourceDeclarationId,
    pub property: SourceOccurrenceId,
    pub receiver_root: String,
    pub members: Vec<String>,
    pub binding: JsTsReceiverBinding,
}

/// An import leaf owns its path and names; this row adds the interpretation
/// needed by the JS/TS binder, including CommonJS replacement semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsImportBindingFact {
    pub import: SourceImportId,
    pub kind: ImportKind,
    pub is_static: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsExportFact {
    pub occurrence: SourceOccurrenceId,
    pub is_esm: bool,
    /// Absent only for an export-star declaration.
    pub name: Option<String>,
    pub kind: JsTsExportKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsTsExportKind {
    Local { local_name: String },
    Default { local_name: Option<String> },
    ReexportNamed { import: SourceImportId },
    ReexportModule { import: SourceImportId },
    Star { import: SourceImportId },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsDeclarationFact {
    pub declaration: SourceDeclarationId,
    pub is_interface: bool,
    pub is_global: bool,
    pub alias_type: Option<JsTsSourceTypeId>,
    pub member_type: Option<JsTsSourceTypeId>,
    pub declared_type: Option<JsTsSourceTypeId>,
    /// None means this declaration has no callable source shape.
    pub parameters: Option<Vec<Option<JsTsSourceTypeId>>>,
    pub return_type: Option<JsTsSourceTypeId>,
    pub component_props: Option<JsTsComponentPropsFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsTsComponentPropsFact {
    Type(JsTsSourceTypeId),
    Named(String),
    Module(SourceImportId),
    TypeMember {
        owner_type: JsTsSourceTypeId,
        members: Vec<String>,
    },
}

define_dense_id! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct JsTsSourceTypeId {
        new: pub,
        get: pub,
        index: pub,
        try_from_index: pub,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsTypeFact {
    pub occurrence: SourceOccurrenceId,
    pub shape: JsTsTypeShape,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsTsTypeShape {
    Named(Vec<String>),
    Generic {
        base: JsTsSourceTypeId,
        arguments: Vec<JsTsSourceTypeId>,
    },
    Wrapped(JsTsSourceTypeId),
    Union(Vec<JsTsSourceTypeId>),
    Intersection(Vec<JsTsSourceTypeId>),
    Query(JsTsSourceTypeId),
    Function {
        parameters: Vec<Option<JsTsSourceTypeId>>,
        result: Option<JsTsSourceTypeId>,
    },
    Object(Vec<(String, JsTsSourceTypeId)>),
    Array(JsTsSourceTypeId),
    Tuple(Vec<JsTsSourceTypeId>),
    NoReceiver,
    Unknown,
}

impl JsTsSourceFacts {
    pub fn estimated_retained_bytes(&self) -> usize {
        self.bindings
            .capacity()
            .saturating_mul(std::mem::size_of::<JsTsImportBindingFact>())
            .saturating_add(
                self.exports
                    .capacity()
                    .saturating_mul(std::mem::size_of::<JsTsExportFact>()),
            )
            .saturating_add(
                self.declarations
                    .capacity()
                    .saturating_mul(std::mem::size_of::<JsTsDeclarationFact>()),
            )
            .saturating_add(
                self.exports
                    .iter()
                    .map(|fact| {
                        fact.name.as_ref().map_or(0, String::capacity)
                            + match &fact.kind {
                                JsTsExportKind::Local { local_name } => local_name.capacity(),
                                JsTsExportKind::Default { local_name } => {
                                    local_name.as_ref().map_or(0, String::capacity)
                                }
                                _ => 0,
                            }
                    })
                    .sum::<usize>(),
            )
            .saturating_add(
                self.declarations
                    .iter()
                    .map(|fact| {
                        fact.parameters.as_ref().map_or(0, |parameters| {
                            parameters.capacity() * std::mem::size_of::<Option<JsTsSourceTypeId>>()
                        }) + match &fact.component_props {
                            Some(JsTsComponentPropsFact::Named(name)) => name.capacity(),
                            Some(JsTsComponentPropsFact::TypeMember { members, .. }) => {
                                members.capacity() * std::mem::size_of::<String>()
                                    + members.iter().map(String::capacity).sum::<usize>()
                            }
                            _ => 0,
                        }
                    })
                    .sum::<usize>(),
            )
            .saturating_add(self.types.capacity() * std::mem::size_of::<JsTsTypeFact>())
            .saturating_add(
                self.types
                    .iter()
                    .map(|fact| match &fact.shape {
                        JsTsTypeShape::Named(names) => {
                            names.capacity() * std::mem::size_of::<String>()
                                + names.iter().map(String::capacity).sum::<usize>()
                        }
                        JsTsTypeShape::Generic { arguments, .. }
                        | JsTsTypeShape::Union(arguments)
                        | JsTsTypeShape::Intersection(arguments)
                        | JsTsTypeShape::Tuple(arguments) => {
                            arguments.capacity() * std::mem::size_of::<JsTsSourceTypeId>()
                        }
                        JsTsTypeShape::Function { parameters, .. } => {
                            parameters.capacity() * std::mem::size_of::<Option<JsTsSourceTypeId>>()
                        }
                        JsTsTypeShape::Object(members) => {
                            members.capacity() * std::mem::size_of::<(String, JsTsSourceTypeId)>()
                                + members
                                    .iter()
                                    .map(|(name, _)| name.capacity())
                                    .sum::<usize>()
                        }
                        _ => 0,
                    })
                    .sum::<usize>(),
            )
            .saturating_add(
                self.declaration_bindings.capacity()
                    * std::mem::size_of::<JsTsDeclarationBindingFact>(),
            )
            .saturating_add(
                self.declaration_bindings
                    .iter()
                    .map(|fact| fact.name.capacity())
                    .sum::<usize>(),
            )
            .saturating_add(
                self.property_receivers.capacity()
                    * std::mem::size_of::<JsTsPropertyReceiverFact>(),
            )
            .saturating_add(
                self.property_receivers
                    .iter()
                    .map(|fact| {
                        fact.receiver_root.capacity()
                            + fact.members.capacity() * std::mem::size_of::<String>()
                            + fact.members.iter().map(String::capacity).sum::<usize>()
                    })
                    .sum::<usize>(),
            )
    }

    pub fn logical_rows(&self) -> usize {
        self.bindings.len()
            + self.exports.len()
            + self.declarations.len()
            + self.types.len()
            + 1
            + self.declaration_bindings.len()
            + self.property_receivers.len()
            + self
                .property_receivers
                .iter()
                .map(|fact| fact.members.len())
                .sum::<usize>()
            + self
                .declarations
                .iter()
                .map(|fact| fact.parameters.as_ref().map_or(0, Vec::len))
                .sum::<usize>()
            + self
                .declarations
                .iter()
                .map(|fact| match &fact.component_props {
                    Some(JsTsComponentPropsFact::TypeMember { members, .. }) => members.len(),
                    _ => 0,
                })
                .sum::<usize>()
            + self
                .types
                .iter()
                .map(|fact| match &fact.shape {
                    JsTsTypeShape::Named(names) => names.len(),
                    JsTsTypeShape::Generic { arguments, .. }
                    | JsTsTypeShape::Union(arguments)
                    | JsTsTypeShape::Intersection(arguments)
                    | JsTsTypeShape::Tuple(arguments) => arguments.len(),
                    JsTsTypeShape::Function { parameters, .. } => parameters.len(),
                    JsTsTypeShape::Object(members) => members.len(),
                    _ => 0,
                })
                .sum::<usize>()
    }
}
