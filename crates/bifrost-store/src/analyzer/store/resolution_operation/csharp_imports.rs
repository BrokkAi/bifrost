//! Dormant C# hooks for the shared, request-local import layers.
use super::imports::*;
use super::*;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionImportSelectorKind;

pub(super) struct CSharpImportBinderRules<'a, 'store, 'input>(
    &'a SelectedResolutionOperation<'store, 'input>,
);
pub(super) struct CSharpImportBindingRules<'a, 'store, 'input>(
    &'a SelectedResolutionOperation<'store, 'input>,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub struct CSharpImportPrecedence {
    // C# is level-first: depth precedes rank, the reverse of the JVM order.
    pub depth: u32,
    pub rank: u32,
}

impl ImportBinderRules for CSharpImportBinderRules<'_, '_, '_> {
    fn lookup_recipes(
        &self,
        fragment: BindingFragmentId,
        route: &[SemanticId],
        demand: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<ResolutionLookupSemanticRecipe>>> {
        let semantics = route.iter().copied().chain([demand]).collect::<Vec<_>>();
        self.0
            .import_lookup_recipes(fragment, &semantics, cancellation, |_| {})
    }
    fn token_metadata(
        &self,
        blob: i64,
        token: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<ImportTokenMetadata>>> {
        self.0.import_token_metadata(
            blob,
            SelectedResolutionMountOrdinal::new(token.ordinal().expect("import token is mounted")),
            token,
            cancellation,
        )
    }
    fn classify(
        &self,
        selector: Option<&SelectedImportSelector>,
        _route: Option<&SelectedImportRoute>,
    ) -> ImportBinderClass {
        ImportBinderClass {
            named: selector.is_some_and(|s| s.kind == ResolutionImportSelectorKind::Named),
            route: None,
        }
    }
}
impl ImportBindingRules for CSharpImportBindingRules<'_, '_, '_> {
    type Precedence = CSharpImportPrecedence;
    fn token_metadata(
        &self,
        blob: i64,
        mount: SelectedResolutionMountOrdinal,
        token: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<ImportTokenMetadata>>> {
        self.0
            .import_token_metadata(blob, mount, token, cancellation)
    }
    fn binder_rank(&self, _language: Language, metadata: &ImportTokenMetadata) -> Option<u32> {
        match metadata.selector.as_ref()?.kind {
            ResolutionImportSelectorKind::Named => Some(0),
            ResolutionImportSelectorKind::Star => Some(1),
            ResolutionImportSelectorKind::ReceiverMember => None,
        }
    }
    fn precedence(&self, depth: u32, rank: u32) -> Self::Precedence {
        CSharpImportPrecedence { depth, rank }
    }
}

#[derive(Debug)]
#[doc(hidden)]
pub struct CSharpImportProbe {
    pub binders: Vec<(Option<String>, Option<String>, bool)>,
    pub bindings: Vec<(usize, CSharpImportPrecedence)>,
    pub references: Vec<usize>,
}

/// Exercise both shared layers against one selected file's authored imports.
#[doc(hidden)]
pub fn probe_imports(
    operation: &SelectedResolutionOperation<'_, '_>,
    path: &str,
    cancellation: &CancellationToken,
) -> Result<Option<CSharpImportProbe>> {
    let Some(mount) = operation.mount_table().mount_for_path("csharp", path)? else {
        return Ok(None);
    };
    let ready = &operation.ready;
    let lexical = ready.lexical_source();
    let mut halves = Vec::new();
    let outcome = crate::analyzer::resolution::visit_selected_root_import_half_pages(
        &ready.context_identities,
        &lexical,
        &lexical,
        Some(&[mount.ordinal()]),
        cancellation,
        &mut FactPageVisitor::new(&mut |page| {
            halves.extend_from_slice(page);
            Ok(true)
        }),
    )?;
    if outcome.is_cancelled() {
        return Ok(None);
    }
    let record = ready.inventory.mount_record_by_ordinal(mount.ordinal())?;
    let Some(binders) = hydrate_import_binders(
        ready,
        &CSharpImportBinderRules(operation),
        record.blob_id(),
        mount.fragment(),
        halves,
        cancellation,
    )?
    else {
        return Ok(None);
    };
    let mut result = CSharpImportProbe {
        binders: Vec::new(),
        bindings: Vec::new(),
        references: ready.inventory.connection().prepare(
            "SELECT DISTINCT site.start_byte FROM resolution_semantic_sites semantic
             JOIN resolution_sites site ON site.blob_id=semantic.blob_id AND site.site=semantic.source_site
             WHERE semantic.blob_id=?1 AND semantic.semantic_role='reference'"
        )?.query_map([record.blob_id()], |row| row.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?,
    };
    let mut seen = HashSet::default();
    for binder in binders {
        let lookup = binder.recipes.last().expect("import has a demand");
        if seen.insert(lookup.semantic(&ready.shared_names())) {
            let Some(bindings) = import_bindings_for_lookup(
                ready,
                &CSharpImportBindingRules(operation),
                mount.ordinal(),
                lookup,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            for binding in bindings {
                let evidence =
                    authored_reference_local_path_evidence(ready, binding.reference, cancellation)?
                        .expect("binding has authored evidence");
                result
                    .bindings
                    .push((evidence.metadata().start_byte(), binding.precedence));
            }
        }
        result
            .binders
            .push((binder.bound, binder.imported, binder.route.is_none()));
    }
    result.bindings.sort_unstable();
    Ok(Some(result))
}
