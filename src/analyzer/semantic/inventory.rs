//! Shared identity and work-accounting mechanics for procedure inventories.
//!
//! Language adapters still own tree traversal and callable recognition. This
//! module owns the syntax-free state that must remain identical across those
//! traversals: declaration paths, sibling ordinals, dense procedure IDs,
//! stable locators, and the distinction between observed enumeration work and
//! the traversal-only work passed into procedure lowering.

use tree_sitter::Node;

use crate::analyzer::ProjectFile;
use crate::hash::HashMap;

use super::lowering::{source_anchor, sum_lowering_work};
use super::{
    DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, ProcedureId, SemanticBudget,
    SemanticBudgetExceeded, SemanticLanguage, SemanticLocator, SemanticProviderError, SemanticRole,
    SemanticWork, SourceAnchor, WorkspaceMountId, WorkspaceRelativePath,
};

/// Result of a language-owned procedure inventory walk.
pub(crate) enum ProcedureInventoryOutcome<T> {
    Complete {
        value: T,
        /// One-time traversal work inherited by procedure lowering.
        initial_work: SemanticWork,
        /// Identity plus traversal work already observed by inventory.
        inventory_work: SemanticWork,
    },
    ExceededBudget {
        exceeded: SemanticBudgetExceeded,
        /// All identity and traversal work observed before stopping.
        work: SemanticWork,
    },
    Cancelled {
        /// All identity and traversal work observed before cancellation.
        work: SemanticWork,
    },
}

/// A successfully allocated procedure identity.
pub(crate) struct ProcedureIdentity {
    pub(crate) id: ProcedureId,
    pub(crate) locator: SemanticLocator,
    pub(crate) declaration_path: usize,
}

/// Budget stop produced by one inventory step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcedureInventoryStop {
    pub(crate) exceeded: SemanticBudgetExceeded,
    pub(crate) work: SemanticWork,
}

impl ProcedureInventoryStop {
    pub(crate) fn into_outcome<T>(self) -> ProcedureInventoryOutcome<T> {
        ProcedureInventoryOutcome::ExceededBudget {
            exceeded: self.exceeded,
            work: self.work,
        }
    }
}

/// Syntax-free state shared by every language's iterative inventory walk.
pub(crate) struct ProcedureInventoryBuilder<'budget> {
    mount: WorkspaceMountId,
    path: WorkspaceRelativePath,
    language: SemanticLanguage,
    siblings: HashMap<(usize, DeclarationSegmentKind, Option<Box<str>>), u32>,
    declaration_paths: Vec<DeclarationPathEntry>,
    identity_work: SemanticWork,
    traversal_work: SemanticWork,
    next_procedure: usize,
    budget: &'budget SemanticBudget,
}

impl<'budget> ProcedureInventoryBuilder<'budget> {
    pub(crate) fn new(
        file: &ProjectFile,
        language: SemanticLanguage,
        root: Node<'_>,
        fallback_file_name: &str,
        budget: &'budget SemanticBudget,
    ) -> Result<Self, SemanticProviderError> {
        let mount = WorkspaceMountId::from_root(file.root());
        let path = WorkspaceRelativePath::try_from_path(file.rel_path())
            .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
        let file_anchor =
            source_anchor(root, 0).map_err(SemanticProviderError::invalid_identity)?;
        let file_name = file
            .rel_path()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(fallback_file_name);
        let file_segment =
            DeclarationSegment::named(DeclarationSegmentKind::File, file_name, file_anchor, 0)
                .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;

        Ok(Self {
            mount,
            path,
            language,
            siblings: HashMap::default(),
            declaration_paths: vec![DeclarationPathEntry {
                parent: None,
                segment: file_segment,
            }],
            identity_work: SemanticWork::default(),
            traversal_work: SemanticWork::default(),
            next_procedure: 0,
            budget,
        })
    }

    pub(crate) const fn root_path(&self) -> usize {
        0
    }

    pub(crate) fn push_container(
        &mut self,
        parent: usize,
        kind: DeclarationSegmentKind,
        name: Option<&str>,
        anchor: SourceAnchor,
    ) -> Result<usize, SemanticProviderError> {
        let ordinal = next_sibling_ordinal(&mut self.siblings, parent, kind, name);
        let segment = declaration_segment(kind, name, anchor, ordinal)
            .map_err(SemanticProviderError::invalid_identity)?;
        Ok(push_declaration_path(
            &mut self.declaration_paths,
            parent,
            segment,
        ))
    }

    pub(crate) fn allocate_procedure(
        &mut self,
        parent: usize,
        kind: DeclarationSegmentKind,
        name: Option<&str>,
        anchor: SourceAnchor,
    ) -> Result<Result<ProcedureIdentity, ProcedureInventoryStop>, SemanticProviderError> {
        let id = ProcedureId::try_from_index(self.next_procedure)
            .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        let ordinal = next_sibling_ordinal(&mut self.siblings, parent, kind, name);
        let segment = declaration_segment(kind, name, anchor, ordinal)
            .map_err(SemanticProviderError::invalid_identity)?;
        let mut segments = collect_declaration_path(&self.declaration_paths, parent);
        segments.push(segment.clone());
        let declaration = DeclarationLocator::new(segments)
            .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
        let locator = SemanticLocator::new(
            self.mount,
            self.path.clone(),
            self.language,
            declaration,
            SemanticRole::Procedure,
            anchor,
        );
        let identity_candidate =
            sum_lowering_work(self.identity_work, procedure_identity_preflight(&locator));
        let observed_candidate = sum_lowering_work(identity_candidate, self.traversal_work);
        if let Err(exceeded) = self.budget.check(observed_candidate) {
            return Ok(Err(ProcedureInventoryStop {
                exceeded,
                work: observed_candidate,
            }));
        }

        self.identity_work = identity_candidate;
        self.next_procedure = self.next_procedure.saturating_add(1);
        let declaration_path = push_declaration_path(&mut self.declaration_paths, parent, segment);
        Ok(Ok(ProcedureIdentity {
            id,
            locator,
            declaration_path,
        }))
    }

    pub(crate) fn charge_traversal(
        &mut self,
        work: SemanticWork,
    ) -> Result<(), ProcedureInventoryStop> {
        let traversal_candidate = sum_lowering_work(self.traversal_work, work);
        let observed_candidate = sum_lowering_work(self.identity_work, traversal_candidate);
        if let Err(exceeded) = self.budget.check(observed_candidate) {
            return Err(ProcedureInventoryStop {
                exceeded,
                work: observed_candidate,
            });
        }
        self.traversal_work = traversal_candidate;
        Ok(())
    }

    pub(crate) fn charge_traversal_entry(&mut self) -> Result<(), ProcedureInventoryStop> {
        self.charge_traversal(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })
    }

    pub(crate) fn observe_additional_work(
        &mut self,
        work: SemanticWork,
    ) -> Result<(), ProcedureInventoryStop> {
        self.charge_traversal(work)
    }

    pub(crate) fn observed_work(&self) -> SemanticWork {
        sum_lowering_work(self.identity_work, self.traversal_work)
    }

    pub(crate) fn complete<T>(self, value: T) -> ProcedureInventoryOutcome<T> {
        ProcedureInventoryOutcome::Complete {
            value,
            initial_work: self.traversal_work,
            inventory_work: self.observed_work(),
        }
    }

    pub(crate) fn cancelled<T>(&self) -> ProcedureInventoryOutcome<T> {
        ProcedureInventoryOutcome::Cancelled {
            work: self.observed_work(),
        }
    }
}

/// One node in the persistent declaration path assembled while adapters walk
/// nested syntax iteratively.
struct DeclarationPathEntry {
    parent: Option<usize>,
    segment: DeclarationSegment,
}

fn push_declaration_path(
    paths: &mut Vec<DeclarationPathEntry>,
    parent: usize,
    segment: DeclarationSegment,
) -> usize {
    let id = paths.len();
    paths.push(DeclarationPathEntry {
        parent: Some(parent),
        segment,
    });
    id
}

fn collect_declaration_path(
    paths: &[DeclarationPathEntry],
    mut path: usize,
) -> Vec<DeclarationSegment> {
    let mut segments = Vec::new();
    loop {
        let entry = &paths[path];
        segments.push(entry.segment.clone());
        let Some(parent) = entry.parent else {
            break;
        };
        path = parent;
    }
    segments.reverse();
    segments
}

fn next_sibling_ordinal(
    siblings: &mut HashMap<(usize, DeclarationSegmentKind, Option<Box<str>>), u32>,
    scope: usize,
    kind: DeclarationSegmentKind,
    name: Option<&str>,
) -> u32 {
    let key = (scope, kind, name.map(Box::<str>::from));
    let next = siblings.entry(key).or_default();
    let ordinal = *next;
    *next += 1;
    ordinal
}

fn declaration_segment(
    kind: DeclarationSegmentKind,
    name: Option<&str>,
    anchor: SourceAnchor,
    sibling_ordinal: u32,
) -> Result<DeclarationSegment, String> {
    match name {
        Some(name) => DeclarationSegment::named(kind, name, anchor, sibling_ordinal)
            .map_err(|error| error.to_string()),
        None => Ok(DeclarationSegment::anonymous(kind, anchor, sibling_ordinal)),
    }
}

/// Work retained for the shared procedure identity rows created by
/// [`super::lowering::ProcedureLoweringSession::start`].
fn procedure_identity_preflight(locator: &SemanticLocator) -> SemanticWork {
    let segments = locator.declaration().segments();
    let locator_text = locator.path().as_str().len().saturating_add(
        segments
            .iter()
            .filter_map(|segment| segment.name())
            .fold(0usize, |total, name| total.saturating_add(name.len())),
    );
    SemanticWork {
        procedures: 1,
        source_mappings: 1,
        evidence: 1,
        // Two empty adjacency offset arrays, one evidence source, and three
        // retained locator copies (procedure, locator index, source mapping).
        nested_entries: 3usize.saturating_add(segments.len().saturating_mul(3)),
        owned_text_bytes: locator_text.saturating_mul(3),
        ..SemanticWork::default()
    }
}
