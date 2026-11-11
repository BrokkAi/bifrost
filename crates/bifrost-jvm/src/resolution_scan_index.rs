//! Per-file catch-up indexes for resolution checks during JVM fact lowering.

use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, ResolutionIdentifierRole, ResolutionSiteId, ResolutionTypeSlotId,
    ResolutionTypeTransferKind,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};

/// Catch-up indexes for one file's lowerer. `type_transfers`,
/// `root_reference_segments` are append-only after publication.
/// `binding_projections` is invalidated after Kotlin's expression refinement
/// changes `output`. `root_references` may edit only fields other than `reference`.
/// `identifiers` may edit only `name`; Scala invalidates after its constructor
/// cleanup removes rows. Java and Scala invalidate when `super_receivers` is
/// taken for hierarchy completion. Every indexed field is otherwise immutable.
#[derive(Default)]
pub(crate) struct ResolutionScanIndex {
    identifier_watermark: usize,
    identifiers: HashMap<(ResolutionSiteId, ResolutionIdentifierRole), Vec<usize>>,
    transfer_watermark: usize,
    transfers: HashSet<(
        ResolutionTypeSlotId,
        ResolutionTypeSlotId,
        ResolutionTypeTransferKind,
    )>,
    transfer_outputs: HashSet<(ResolutionTypeSlotId, ResolutionTypeTransferKind)>,
    root_watermark: usize,
    roots: HashSet<ResolutionSiteId>,
    root_segment_watermark: usize,
    root_segments: HashSet<ResolutionSiteId>,
    projection_watermark: usize,
    projections: HashSet<(ResolutionSiteId, ResolutionTypeSlotId)>,
    super_watermark: usize,
    super_outputs: HashSet<ResolutionTypeSlotId>,
}

impl ResolutionScanIndex {
    pub(crate) fn invalidate_identifiers(&mut self) {
        self.identifier_watermark = 0;
        self.identifiers.clear();
    }

    pub(crate) fn invalidate_projections(&mut self) {
        self.projection_watermark = 0;
        self.projections.clear();
    }

    pub(crate) fn invalidate_super_receivers(&mut self) {
        self.super_watermark = 0;
        self.super_outputs.clear();
    }

    fn catch_up_identifiers(&mut self, facts: &FileResolutionFacts) {
        let rows = &facts.identifiers;
        assert!(rows.len() >= self.identifier_watermark);
        for (position, row) in rows.iter().enumerate().skip(self.identifier_watermark) {
            self.identifiers
                .entry((row.site, row.role))
                .or_default()
                .push(position);
        }
        self.identifier_watermark = rows.len();
    }

    pub(crate) fn has_identifier(
        &mut self,
        facts: &FileResolutionFacts,
        site: ResolutionSiteId,
        role: ResolutionIdentifierRole,
    ) -> bool {
        self.catch_up_identifiers(facts);
        self.identifiers.contains_key(&(site, role))
    }

    pub(crate) fn first_qualifier(
        &mut self,
        facts: &FileResolutionFacts,
        site: ResolutionSiteId,
        role: ResolutionIdentifierRole,
    ) -> Option<Option<ResolutionTypeSlotId>> {
        self.catch_up_identifiers(facts);
        self.identifiers
            .get(&(site, role))
            .and_then(|positions| positions.first())
            .map(|&position| facts.identifiers[position].qualifier)
    }

    pub(crate) fn has_identifier_qualifier(
        &mut self,
        facts: &FileResolutionFacts,
        site: ResolutionSiteId,
        role: ResolutionIdentifierRole,
        qualifier: Option<ResolutionTypeSlotId>,
    ) -> bool {
        self.catch_up_identifiers(facts);
        self.identifiers
            .get(&(site, role))
            .is_some_and(|positions| {
                positions
                    .iter()
                    .any(|&position| facts.identifiers[position].qualifier == qualifier)
            })
    }

    pub(crate) fn has_identifier_qualifier_site(
        &mut self,
        facts: &FileResolutionFacts,
        site: ResolutionSiteId,
        role: ResolutionIdentifierRole,
        qualifier_site: ResolutionSiteId,
    ) -> bool {
        self.catch_up_identifiers(facts);
        self.identifiers
            .get(&(site, role))
            .is_some_and(|positions| {
                positions.iter().any(|&position| {
                    facts.identifiers[position]
                        .qualifier
                        .is_some_and(|slot| facts.type_slots[slot.index()].site == qualifier_site)
                })
            })
    }

    fn catch_up_transfers(&mut self, facts: &FileResolutionFacts) {
        let rows = &facts.type_transfers;
        assert!(rows.len() >= self.transfer_watermark);
        for row in &rows[self.transfer_watermark..] {
            self.transfers.insert((row.input, row.output, row.kind));
            self.transfer_outputs.insert((row.output, row.kind));
        }
        self.transfer_watermark = rows.len();
    }

    pub(crate) fn has_transfer(
        &mut self,
        facts: &FileResolutionFacts,
        input: ResolutionTypeSlotId,
        output: ResolutionTypeSlotId,
        kind: ResolutionTypeTransferKind,
    ) -> bool {
        self.catch_up_transfers(facts);
        self.transfers.contains(&(input, output, kind))
    }

    pub(crate) fn has_transfer_output(
        &mut self,
        facts: &FileResolutionFacts,
        output: ResolutionTypeSlotId,
        kind: ResolutionTypeTransferKind,
    ) -> bool {
        self.catch_up_transfers(facts);
        self.transfer_outputs.contains(&(output, kind))
    }

    pub(crate) fn has_root(&mut self, facts: &FileResolutionFacts, site: ResolutionSiteId) -> bool {
        let rows = &facts.root_references;
        assert!(rows.len() >= self.root_watermark);
        for row in &rows[self.root_watermark..] {
            self.roots.insert(row.reference);
        }
        self.root_watermark = rows.len();
        let segments = &facts.root_reference_segments;
        assert!(segments.len() >= self.root_segment_watermark);
        for row in &segments[self.root_segment_watermark..] {
            self.root_segments.insert(row.reference);
        }
        self.root_segment_watermark = segments.len();
        self.roots.contains(&site) || self.root_segments.contains(&site)
    }

    pub(crate) fn has_root_reference(
        &mut self,
        facts: &FileResolutionFacts,
        site: ResolutionSiteId,
    ) -> bool {
        let rows = &facts.root_references;
        assert!(rows.len() >= self.root_watermark);
        for row in &rows[self.root_watermark..] {
            self.roots.insert(row.reference);
        }
        self.root_watermark = rows.len();
        self.roots.contains(&site)
    }

    pub(crate) fn has_projection(
        &mut self,
        facts: &FileResolutionFacts,
        site: ResolutionSiteId,
        output: ResolutionTypeSlotId,
    ) -> bool {
        let rows = &facts.binding_projections;
        assert!(rows.len() >= self.projection_watermark);
        for row in &rows[self.projection_watermark..] {
            self.projections.insert((row.reference, row.output));
        }
        self.projection_watermark = rows.len();
        self.projections.contains(&(site, output))
    }

    pub(crate) fn has_super_receiver(
        &mut self,
        receivers: &[(ResolutionSiteId, ResolutionTypeSlotId)],
        output: ResolutionTypeSlotId,
    ) -> bool {
        assert!(receivers.len() >= self.super_watermark);
        for &(_, slot) in &receivers[self.super_watermark..] {
            self.super_outputs.insert(slot);
        }
        self.super_watermark = receivers.len();
        self.super_outputs.contains(&output)
    }
}
