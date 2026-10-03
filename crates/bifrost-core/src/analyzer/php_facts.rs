//! Content-local PHP declaration properties owned by the primary extraction.

use crate::analyzer::dense_id::define_dense_id;
use crate::analyzer::parsed_file::SourceImportFact;
use crate::analyzer::source_facts::{
    SourceDeclarationId, SourceFactRows, SourceImportId, SourceOccurrenceId,
};

pub const PHP_SOURCE_FACTS_VERSION: i64 = 1;

define_dense_id! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PhpSourceContextId {
        new: pub,
        get: pub,
        index: pub,
        try_from_index: pub,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhpAliasKind {
    Type,
    Function,
    Constant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpAliasSourceFact {
    pub import: SourceImportId,
    pub kind: PhpAliasKind,
}

impl PhpAliasSourceFact {
    /// The alias kind is PHP-specific; the binder and target path have one
    /// authority in the shared canonical source-import arena.
    pub fn binding<'a>(&self, imports: &'a [SourceImportFact]) -> (&'a str, String) {
        let import = &imports[self.import.index()];
        let local = import
            .alias
            .as_deref()
            .or(import.identifier.as_deref())
            .expect("PHP alias references a source import binder");
        let path = import
            .path
            .as_ref()
            .expect("PHP alias references an interpreted import path");
        (local, path.segments.join("."))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpContextSourceFact {
    pub namespace: String,
    /// Dense indices into the one file-local alias arena, in source order.
    pub aliases: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhpDeclarationKind {
    Class,
    Interface,
    Trait,
    Enum,
    Function,
    Method,
    Property,
    Constant,
    EnumCase,
    PromotedProperty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhpDeclaredSourceType {
    Unknown,
    Nominal(Vec<String>),
    DynamicObject,
    DynamicMixed,
    SelfType,
    StaticType,
    ParentType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpDeclarationSourceFact {
    pub declaration: SourceDeclarationId,
    pub kind: PhpDeclarationKind,
    pub context: PhpSourceContextId,
    /// Exact type syntax provenance; the interpretation below is derived
    /// file-locally and never claims cross-file resolution.
    pub declared_type_occurrence: Option<SourceOccurrenceId>,
    pub declared_type: PhpDeclaredSourceType,
    pub supertypes: Vec<String>,
    pub class_parent: Option<String>,
    pub has_trait_use: bool,
    /// Nominal and collection-element names derived from PHPDoc on this
    /// exact declaration. They are absent for unsupported PHPDoc shapes.
    pub doc_nominal_type: Option<String>,
    pub doc_element_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhpFieldWriteKind {
    Instance,
    Static,
    Indexed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpFieldWriteSourceFact {
    pub occurrence: SourceOccurrenceId,
    pub class: SourceDeclarationId,
    pub field: String,
    pub kind: PhpFieldWriteKind,
    pub directly_in_constructor: bool,
    pub value_type: PhpDeclaredSourceType,
    pub doc_element_type: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhpSourceFacts {
    pub writes: Vec<PhpFieldWriteSourceFact>,
    pub contexts: Vec<PhpContextSourceFact>,
    pub aliases: Vec<PhpAliasSourceFact>,
    pub declarations: Vec<PhpDeclarationSourceFact>,
}

impl PhpSourceFacts {
    pub fn valid_links(&self, source: &SourceFactRows, imports: &[SourceImportFact]) -> bool {
        use crate::hash::{HashMap, HashSet};
        fn valid_type(ty: &PhpDeclaredSourceType) -> bool {
            match ty {
                PhpDeclaredSourceType::Nominal(arms) => {
                    !arms.is_empty()
                        && arms.iter().all(|arm| !arm.is_empty())
                        && arms.iter().collect::<HashSet<_>>().len() == arms.len()
                }
                _ => true,
            }
        }
        let declarations = self
            .declarations
            .iter()
            .map(|declaration| (declaration.declaration, declaration.kind))
            .collect::<HashMap<_, _>>();
        declarations.len() == self.declarations.len()
            && self.writes.iter().all(|write| {
                write.occurrence.index() < source.occurrence_count()
                    && declarations.get(&write.class) == Some(&PhpDeclarationKind::Class)
                    && !write.field.is_empty()
                    && valid_type(&write.value_type)
            })
            && self
                .aliases
                .iter()
                .map(|alias| alias.import)
                .collect::<HashSet<_>>()
                .len()
                == self.aliases.len()
            && self.aliases.iter().all(|alias| {
                imports.get(alias.import.index()).is_some_and(|import| {
                    import
                        .path
                        .as_ref()
                        .is_some_and(|path| !path.segments.is_empty())
                        && import
                            .alias
                            .as_ref()
                            .or(import.identifier.as_ref())
                            .is_some_and(|name| !name.is_empty())
                })
            })
            && self.contexts.iter().all(|context| {
                context
                    .aliases
                    .iter()
                    .all(|alias| (*alias as usize) < self.aliases.len())
                    && context.aliases.windows(2).all(|pair| pair[0] < pair[1])
            })
            && self.declarations.iter().all(|declaration| {
                declaration.declaration.index() < source.declaration_count()
                    && declaration.context.index() < self.contexts.len()
                    && declaration
                        .declared_type_occurrence
                        .is_none_or(|occurrence| occurrence.index() < source.occurrence_count())
                    && (declaration.declared_type_occurrence.is_some()
                        || declaration.declared_type == PhpDeclaredSourceType::Unknown)
                    && valid_type(&declaration.declared_type)
                    && declaration
                        .supertypes
                        .iter()
                        .all(|supertype| !supertype.is_empty())
                    && declaration.class_parent.as_ref().is_none_or(|parent| {
                        declaration.kind == PhpDeclarationKind::Class
                            && declaration.supertypes.contains(parent)
                    })
            })
    }

    pub fn estimated_retained_bytes(&self) -> usize {
        self.writes.capacity() * std::mem::size_of::<PhpFieldWriteSourceFact>()
            + self
                .writes
                .iter()
                .map(|write| {
                    write.field.capacity()
                        + write.doc_element_type.as_ref().map_or(0, String::capacity)
                        + match &write.value_type {
                            PhpDeclaredSourceType::Nominal(arms) => {
                                arms.capacity() * std::mem::size_of::<String>()
                                    + arms.iter().map(String::capacity).sum::<usize>()
                            }
                            _ => 0,
                        }
                })
                .sum::<usize>()
            + self.contexts.capacity() * std::mem::size_of::<PhpContextSourceFact>()
            + self.aliases.capacity() * std::mem::size_of::<PhpAliasSourceFact>()
            + self.declarations.capacity() * std::mem::size_of::<PhpDeclarationSourceFact>()
            + self
                .contexts
                .iter()
                .map(|context| {
                    context.namespace.capacity()
                        + context.aliases.capacity() * std::mem::size_of::<u32>()
                })
                .sum::<usize>()
            + self
                .declarations
                .iter()
                .map(|declaration| {
                    declaration.supertypes.capacity() * std::mem::size_of::<String>()
                        + declaration
                            .supertypes
                            .iter()
                            .map(String::capacity)
                            .sum::<usize>()
                        + declaration
                            .class_parent
                            .as_ref()
                            .map_or(0, String::capacity)
                        + declaration
                            .doc_nominal_type
                            .as_ref()
                            .map_or(0, String::capacity)
                        + declaration
                            .doc_element_type
                            .as_ref()
                            .map_or(0, String::capacity)
                        + match &declaration.declared_type {
                            PhpDeclaredSourceType::Nominal(arms) => {
                                arms.capacity() * std::mem::size_of::<String>()
                                    + arms.iter().map(String::capacity).sum::<usize>()
                            }
                            _ => 0,
                        }
                })
                .sum::<usize>()
    }
}
