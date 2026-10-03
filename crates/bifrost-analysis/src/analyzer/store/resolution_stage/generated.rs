//! Generated include and macro bridges allocated and published as one unit.

use super::{SelectedResolutionStage, allocation};
use crate::CancellationToken;
use crate::analyzer::resolution::{
    BindingNodeId, BindingNodeKind, CandidatePathIdentity, LoweredResolutionFragment, PartialPath,
    PartialPathId, ResolutionIdentityCatalog, ResolutionIdentityCatalogBuilder,
    ResolutionNodeIdentity, ResolutionPathIdentity, ResolutionRegisteredIdentities, SemanticId,
    retarget_lexical,
};
use crate::analyzer::store::Result;
use crate::analyzer::store::resolution_selection::SelectedResolutionMountRecord;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use rusqlite::{Connection, OptionalExtension, params};

impl SelectedResolutionStage<'_, '_> {
    pub(crate) fn admit_include_glob(
        &self,
        host: &SelectedResolutionMountRecord,
        lexical: LoweredResolutionFragment,
        catalog: ResolutionIdentityCatalog,
        cancellation: &CancellationToken,
    ) -> Result<Option<(CandidatePathIdentity, PartialPath)>> {
        assert_eq!(lexical.fragment(), host.fragment_id());
        assert_eq!(catalog.fragment(), host.fragment_id());
        assert_eq!(
            lexical.paths().len(),
            1,
            "one include glob produces one path"
        );
        assert_eq!(catalog.paths().len(), 1);
        let bridge_identity = catalog
            .path_identity(lexical.paths()[0].0)
            .expect("include glob path has producer identity")
            .digest();
        self.with_generated_admission(cancellation, |connection| {
            let producer = connection.prepare_cached(
                "SELECT producer_id FROM temp.selected_resolution_stage_producers WHERE host_ordinal=?1 AND bridge_identity=?2",
            )?.query_row(params![host.ordinal().get(), bridge_identity], |row| row.get::<_, i64>(0)).optional()?;
            let assigned = match producer {
                Some(producer) => allocation::replay_catalog(
                    self.selection, connection, producer, host.ordinal(), &catalog, cancellation,
                )?,
                None => allocation::assign_catalog(
                    self.selection, connection, host.ordinal(), &catalog, cancellation,
                )?,
            };
            let Some(assigned) = assigned else { return Ok(None) };
            let Some(lexical) = retarget_lexical(lexical, &assigned, cancellation) else {
                return Ok(None);
            };
            let catalog = catalog.retargeted(&assigned);
            let Some(changed) = self.project_generated_bridge(
                connection, host, bridge_identity, &lexical, Some(&catalog),
                catalog.lookup_recipes(), &[], cancellation,
            )? else { return Ok(None) };
            let (path, body) = &lexical.paths()[0];
            Ok(Some(((CandidatePathIdentity::new(host.fragment_id(), *path), body.clone()), changed)))
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_macro_head_pair(
        &self,
        source_host: &SelectedResolutionMountRecord,
        reference: SemanticId,
        reference_node: BindingNodeId,
        definition_host: &SelectedResolutionMountRecord,
        definition: SemanticId,
        definition_node: BindingNodeId,
        cancellation: &CancellationToken,
    ) -> Result<Option<()>> {
        let mut hash = CanonicalHasher::new(b"bifrost-selected-textual-macro-head:v1");
        hash.field("reference", &reference.as_bytes());
        hash.field("definition", &definition.as_bytes());
        let source_identity = ResolutionPathIdentity::new(hash.finish());
        let boundary_identity = ResolutionNodeIdentity::new(source_identity.digest());
        let mut hash = CanonicalHasher::new(b"bifrost-selected-textual-macro-target:v1");
        hash.field("bridge", &source_identity.digest());
        let target_identity = ResolutionPathIdentity::new(hash.finish());
        self.with_generated_admission(cancellation, |connection| {
            // Keep the operation's path-before-node allocation order.
            let Some(source_path) = allocation::assign_path(
                self.selection,
                connection,
                source_host.ordinal(),
                source_identity,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let Some(boundary) = allocation::assign_node(
                self.selection,
                connection,
                source_host.ordinal(),
                boundary_identity,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let source_catalog = self.generated_catalog(
                connection,
                source_host,
                &[(boundary, boundary_identity)],
                &[(source_path, source_identity)],
            );
            let source = LoweredResolutionFragment::selected_macro_head_bridge(
                source_host.fragment_id(),
                reference,
                reference_node,
                boundary,
                source_path,
            );
            let Some(source_changed) = self.project_generated_bridge(
                connection,
                source_host,
                source_identity.digest(),
                &source,
                Some(&source_catalog),
                &[],
                &[],
                cancellation,
            )?
            else {
                return Ok(None);
            };
            // Publish the first correspondence before allocating the other half,
            // including when both hosts are the same selected mount.
            let Some(target_path) = allocation::assign_path(
                self.selection,
                connection,
                definition_host.ordinal(),
                target_identity,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let target_catalog = self.generated_catalog(
                connection,
                definition_host,
                &[],
                &[(target_path, target_identity)],
            );
            let target = LoweredResolutionFragment::selected_macro_head_definition(
                definition_host.fragment_id(),
                definition,
                definition_node,
                boundary,
                target_path,
            );
            let Some(target_changed) = self.project_generated_bridge(
                connection,
                definition_host,
                target_identity.digest(),
                &target,
                Some(&target_catalog),
                &[],
                &[],
                cancellation,
            )?
            else {
                return Ok(None);
            };
            Ok(Some(((), source_changed || target_changed)))
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_include_binding_pair(
        &self,
        destination_host: &SelectedResolutionMountRecord,
        destination: BindingNodeId,
        origin_host: &SelectedResolutionMountRecord,
        original_identity: CandidatePathIdentity,
        original: &PartialPath,
        end_kind: BindingNodeKind,
        cancellation: &CancellationToken,
    ) -> Result<Option<()>> {
        assert_eq!(original_identity.fragment(), origin_host.fragment_id());
        let mut hash = CanonicalHasher::new(b"bifrost-selected-include-binding:v1");
        hash.field("path", &original_identity.path().as_bytes());
        hash.field("scope", &destination.as_bytes());
        let source_identity = ResolutionPathIdentity::new(hash.finish());
        let boundary_identity = ResolutionNodeIdentity::new(source_identity.digest());
        let mut hash = CanonicalHasher::new(b"bifrost-selected-include-continuation:v1");
        hash.field("binding", &source_identity.digest());
        let target_identity = ResolutionPathIdentity::new(hash.finish());
        self.with_generated_admission(cancellation, |connection| {
            // Include splices historically allocate the boundary before paths.
            let Some(boundary) = allocation::assign_node(
                self.selection,
                connection,
                destination_host.ordinal(),
                boundary_identity,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let Some(source_path) = allocation::assign_path(
                self.selection,
                connection,
                destination_host.ordinal(),
                source_identity,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let source_catalog = self.generated_catalog(
                connection,
                destination_host,
                &[(boundary, boundary_identity)],
                &[(source_path, source_identity)],
            );
            let source = LoweredResolutionFragment::selected_include_binding(
                destination_host.fragment_id(),
                destination,
                boundary,
                source_path,
                original,
            );
            let Some(source_changed) = self.project_generated_bridge(
                connection,
                destination_host,
                source_identity.digest(),
                &source,
                Some(&source_catalog),
                &[],
                &[],
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let Some(target_path) = allocation::assign_path(
                self.selection,
                connection,
                origin_host.ordinal(),
                target_identity,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let target_catalog = self.generated_catalog(
                connection,
                origin_host,
                &[],
                &[(target_path, target_identity)],
            );
            let target = LoweredResolutionFragment::selected_include_continuation(
                origin_host.fragment_id(),
                boundary,
                target_path,
                end_kind,
                original,
            );
            let Some(target_changed) = self.project_generated_bridge(
                connection,
                origin_host,
                target_identity.digest(),
                &target,
                Some(&target_catalog),
                &[],
                &[],
                cancellation,
            )?
            else {
                return Ok(None);
            };
            Ok(Some(((), source_changed || target_changed)))
        })
    }

    /// Only descriptors of coordinates actually invented by this bridge belong
    /// here. Borrowed endpoint nodes and semantics keep their original authority.
    fn generated_catalog(
        &self,
        connection: &Connection,
        host: &SelectedResolutionMountRecord,
        nodes: &[(BindingNodeId, ResolutionNodeIdentity)],
        paths: &[(PartialPathId, ResolutionPathIdentity)],
    ) -> ResolutionIdentityCatalog {
        let names = self.selection.shared_name_table().interner(connection);
        let mut builder = ResolutionIdentityCatalogBuilder::new(host.fragment_id(), &names);
        let mut assigned = ResolutionRegisteredIdentities::new(host.fragment_id());
        for &(node, identity) in nodes {
            assigned.assign_node(builder.node(identity), node);
        }
        for &(path, identity) in paths {
            assigned.assign_path(builder.path(identity), path);
        }
        // This translates only the tiny catalog. No borrowed body is passed
        // through a mapping whose provisional IDs might overlap its coordinates.
        builder.finish().retargeted(&assigned)
    }
}

#[cfg(test)]
#[path = "generated_tests.rs"]
mod tests;
