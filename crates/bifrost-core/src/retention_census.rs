//! Explicit, invocation-scoped structural memory census for test support.
//!
//! This module is compiled only for unit tests or the `test-support` feature.
//! It has no global registry and is not connected to cache admission or normal
//! execution. Callers identify the allocation itself (for example, the inner
//! value referenced by an `Arc`), not its ownership wrapper.

use serde::Serialize;
use std::any::{Any, TypeId};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::marker::PhantomData;
use std::sync::Arc;

/// Lifetime of a family's observed state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FamilyLifetime {
    /// May be retained between requests.
    Persistent,
    /// Exists only for one request.
    RequestOnly,
    /// Exists only for a provider's request-scoped work.
    ProviderOnly,
}

/// Whether an allocation is charged by the owner's budget already.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationAccounting {
    /// Structural capacity owned by this cache family and not charged elsewhere.
    OutsideBudget,
    /// Backing bytes already charged through the owner's retention budget.
    AlreadyBudgeted,
}

/// Why an observation cannot contribute a known byte count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownKind {
    /// The measurement does not cover all relevant state.
    Coverage,
    /// Native or otherwise uninspectable storage has no structural estimate.
    NativeBytes,
    /// An active pin keeps state alive but its count or size is unavailable.
    ActivePins,
    /// Repeated observations of one allocation disagree.
    ConflictingObservation,
    /// One family was assigned incompatible lifetimes.
    FamilyLifetime,
}

/// An explicit reason a family's census is incomplete.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct UnknownReason {
    pub kind: UnknownKind,
    pub reason: &'static str,
}

/// Unit used to interpret a separate cache-residency weight.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidentWeightUnit {
    /// Weight is an explicit estimated byte count, not the structural census.
    BytesEstimate,
    /// Weight is an entry count or other non-byte unit.
    Entries,
}

/// A cache's own residency reading. These readings do not contribute to the
/// deduplicated structural allocation totals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResidentReading {
    pub family: &'static str,
    pub count: u64,
    pub weight: u64,
    pub weight_unit: ResidentWeightUnit,
}

/// One family summary. Byte columns include every full allocation owned by
/// the family, so they are intentionally non-additive when allocations are
/// shared. Use the report's union totals for deduplicated sums.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FamilySummary {
    pub family: &'static str,
    /// `None` means inconsistent lifetime declarations were observed.
    pub lifetime: Option<FamilyLifetime>,
    pub cache_owned_capacity_bytes: u64,
    pub already_accounted_backing_bytes: u64,
    /// Distinct reasons for unknown active pins; this is not a pin count.
    pub unknown_active_pins: Vec<&'static str>,
    pub unknown_reasons: Vec<UnknownReason>,
}

/// A logical allocation and all cache families that own or reference it.
/// Identity addresses are deliberately omitted from reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AllocationGroup {
    /// `None` when repeated observations disagreed on allocation kind.
    pub kind: Option<&'static str>,
    /// `None` when size/accounting observations conflict.
    pub estimated_bytes: Option<u64>,
    /// `None` when size/accounting observations conflict.
    pub accounting: Option<AllocationAccounting>,
    /// Sorted, complete set of families that reported this allocation.
    pub families: Vec<&'static str>,
    pub unknown_reasons: Vec<UnknownReason>,
}

/// Ephemeral count totals across each unique, known allocation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CensusTotals {
    pub cache_owned_capacity_bytes: u64,
    pub already_accounted_backing_bytes: u64,
    pub known_bytes: u64,
}

/// Stable, sorted result of a census invocation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RetentionCensusReport {
    pub families: Vec<FamilySummary>,
    pub resident_readings: Vec<ResidentReading>,
    /// All known and unknown allocations, sorted by reported properties.
    pub allocation_groups: Vec<AllocationGroup>,
    /// Deduplicated across allocation identities; unknown/conflicting
    /// allocations are excluded rather than assigned a guessed value.
    pub union: CensusTotals,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct AllocationIdentity {
    type_id: TypeId,
    address: usize,
}

#[derive(Default)]
struct FamilyState {
    lifetime: FamilyLifetimeState,
    unknown_active_pins: BTreeSet<&'static str>,
    unknown_reasons: BTreeSet<UnknownReason>,
}

#[derive(Default)]
enum FamilyLifetimeState {
    #[default]
    Unset,
    Known(FamilyLifetime),
    Conflict,
}

impl FamilyState {
    fn declare_lifetime(&mut self, lifetime: FamilyLifetime) {
        match self.lifetime {
            FamilyLifetimeState::Unset => self.lifetime = FamilyLifetimeState::Known(lifetime),
            FamilyLifetimeState::Known(previous) if previous == lifetime => {}
            FamilyLifetimeState::Known(_) => {
                self.lifetime = FamilyLifetimeState::Conflict;
                self.unknown_reasons.insert(UnknownReason {
                    kind: UnknownKind::FamilyLifetime,
                    reason: "family_lifetime_disagreed",
                });
            }
            FamilyLifetimeState::Conflict => {}
        }
    }
}

struct AllocationObservation {
    kind: Option<&'static str>,
    estimated_bytes: u64,
    accounting: AllocationAccounting,
    families: BTreeSet<&'static str>,
    unknown_reasons: BTreeSet<UnknownReason>,
}

/// One explicitly invoked census. It retains only observations for this
/// invocation and produces no global state or admission/accounting effects.
#[derive(Default)]
pub struct RetentionCensus<'allocation> {
    allocations: HashMap<AllocationIdentity, AllocationObservation>,
    families: BTreeMap<&'static str, FamilyState>,
    resident_readings: Vec<ResidentReading>,
    allocation_pins: Vec<Arc<dyn Any + Send + Sync>>,
    _allocation_borrows: PhantomData<&'allocation ()>,
}

impl<'allocation> RetentionCensus<'allocation> {
    pub fn new() -> Self {
        Self::default()
    }

    fn declare_family(&mut self, family: &'static str, lifetime: FamilyLifetime) {
        self.families
            .entry(family)
            .or_default()
            .declare_lifetime(lifetime);
    }

    /// Record a structural estimate for an allocation.
    ///
    /// Pass a reference to the allocation itself, not an `Arc`, cache entry,
    /// or other wrapper. The key includes `T`'s `TypeId`, so distinct object
    /// types at a reused address do not alias. Repeated observations merge all
    /// owners. A kind, size, or accounting disagreement makes the group
    /// unknown and removes it from known union totals. The borrow lasts for
    /// the census lifetime, preventing address reuse while the observation is
    /// retained.
    pub fn record_allocation<T: 'static>(
        &mut self,
        allocation: &'allocation T,
        family: &'static str,
        lifetime: FamilyLifetime,
        kind: &'static str,
        estimated_bytes: u64,
        accounting: AllocationAccounting,
    ) {
        let identity = AllocationIdentity {
            type_id: TypeId::of::<T>(),
            address: allocation as *const T as usize,
        };
        self.record_identity(
            identity,
            family,
            lifetime,
            kind,
            estimated_bytes,
            accounting,
        );
    }

    /// Record an Arc-owned allocation and pin it until [`Self::finish`] returns.
    ///
    /// The key is the inner allocation's concrete type and address. Pass an
    /// `Arc` to the allocation itself, not to a wrapper that merely points at
    /// it. The census keeps an erased strong reference only for this invocation,
    /// allowing callers to release cache/container locks before traversing.
    pub fn record_arc_allocation<T: Any + Send + Sync>(
        &mut self,
        allocation: Arc<T>,
        family: &'static str,
        lifetime: FamilyLifetime,
        kind: &'static str,
        estimated_bytes: u64,
        accounting: AllocationAccounting,
    ) {
        let identity = AllocationIdentity {
            type_id: TypeId::of::<T>(),
            address: Arc::as_ptr(&allocation) as usize,
        };
        let first_pin = !self.allocations.contains_key(&identity);
        self.record_identity(
            identity,
            family,
            lifetime,
            kind,
            estimated_bytes,
            accounting,
        );
        if first_pin {
            let pinned: Arc<dyn Any + Send + Sync> = allocation;
            self.allocation_pins.push(pinned);
        }
    }

    fn record_identity(
        &mut self,
        identity: AllocationIdentity,
        family: &'static str,
        lifetime: FamilyLifetime,
        kind: &'static str,
        estimated_bytes: u64,
        accounting: AllocationAccounting,
    ) {
        self.declare_family(family, lifetime);
        let observation = self.allocations.entry(identity).or_insert_with(|| {
            let mut families = BTreeSet::new();
            families.insert(family);
            AllocationObservation {
                kind: Some(kind),
                estimated_bytes,
                accounting,
                families,
                unknown_reasons: BTreeSet::new(),
            }
        });
        observation.families.insert(family);
        if observation.kind != Some(kind) {
            observation.kind = None;
            observation.unknown_reasons.insert(UnknownReason {
                kind: UnknownKind::ConflictingObservation,
                reason: "allocation_kind_disagreed",
            });
        }
        if observation.estimated_bytes != estimated_bytes {
            observation.unknown_reasons.insert(UnknownReason {
                kind: UnknownKind::ConflictingObservation,
                reason: "allocation_size_disagreed",
            });
        }
        if observation.accounting != accounting {
            observation.unknown_reasons.insert(UnknownReason {
                kind: UnknownKind::ConflictingObservation,
                reason: "allocation_accounting_disagreed",
            });
        }
    }

    /// Mark a family's coverage, native storage, or active pins as unknown.
    /// Unknowns are reasons in the report, never zero-byte observations.
    pub fn record_unknown(
        &mut self,
        family: &'static str,
        lifetime: FamilyLifetime,
        kind: UnknownKind,
        reason: &'static str,
    ) {
        self.declare_family(family, lifetime);
        let state = self.families.get_mut(family).expect("family was declared");
        let inserted = UnknownReason { kind, reason };
        if kind == UnknownKind::ActivePins {
            state.unknown_active_pins.insert(reason);
        } else {
            state.unknown_reasons.insert(inserted);
        }
    }

    /// Record an independent residency view. Its `weight_unit` is explicit;
    /// it is reported separately and never added to structural byte totals.
    pub fn record_resident_reading(
        &mut self,
        family: &'static str,
        lifetime: FamilyLifetime,
        count: u64,
        weight: u64,
        weight_unit: ResidentWeightUnit,
    ) {
        self.declare_family(family, lifetime);
        self.resident_readings.push(ResidentReading {
            family,
            count,
            weight,
            weight_unit,
        });
    }

    /// Consume this invocation and return a stable report without raw pointers.
    pub fn finish(self) -> RetentionCensusReport {
        let mut report = RetentionCensusReport::default();
        for (name, state) in self.families {
            report.families.push(FamilySummary {
                family: name,
                lifetime: match state.lifetime {
                    FamilyLifetimeState::Unset | FamilyLifetimeState::Conflict => None,
                    FamilyLifetimeState::Known(lifetime) => Some(lifetime),
                },
                cache_owned_capacity_bytes: 0,
                already_accounted_backing_bytes: 0,
                unknown_active_pins: state.unknown_active_pins.into_iter().collect(),
                unknown_reasons: state.unknown_reasons.into_iter().collect(),
            });
        }

        for allocation in self.allocations.into_values() {
            let families = allocation.families.into_iter().collect::<Vec<_>>();
            let is_known = allocation.unknown_reasons.is_empty();
            let (estimated_bytes, accounting) = if is_known {
                (
                    Some(allocation.estimated_bytes),
                    Some(allocation.accounting),
                )
            } else {
                for family in &families {
                    let state = report
                        .families
                        .binary_search_by_key(family, |summary| summary.family)
                        .map(|index| &mut report.families[index])
                        .expect("every allocation family was declared");
                    state
                        .unknown_reasons
                        .extend(allocation.unknown_reasons.iter().cloned());
                    state.unknown_reasons.sort();
                    state.unknown_reasons.dedup();
                }
                (None, None)
            };

            if let (Some(bytes), Some(accounting)) = (estimated_bytes, accounting) {
                match accounting {
                    AllocationAccounting::OutsideBudget => {
                        report.union.cache_owned_capacity_bytes = report
                            .union
                            .cache_owned_capacity_bytes
                            .saturating_add(bytes);
                        for family in &families {
                            let index = report
                                .families
                                .binary_search_by_key(family, |summary| summary.family)
                                .expect("every allocation family was declared");
                            report.families[index].cache_owned_capacity_bytes = report.families
                                [index]
                                .cache_owned_capacity_bytes
                                .saturating_add(bytes);
                        }
                    }
                    AllocationAccounting::AlreadyBudgeted => {
                        report.union.already_accounted_backing_bytes = report
                            .union
                            .already_accounted_backing_bytes
                            .saturating_add(bytes);
                        for family in &families {
                            let index = report
                                .families
                                .binary_search_by_key(family, |summary| summary.family)
                                .expect("every allocation family was declared");
                            report.families[index].already_accounted_backing_bytes = report
                                .families[index]
                                .already_accounted_backing_bytes
                                .saturating_add(bytes);
                        }
                    }
                }
                report.union.known_bytes = report.union.known_bytes.saturating_add(bytes);
            }

            report.allocation_groups.push(AllocationGroup {
                kind: allocation.kind,
                estimated_bytes,
                accounting,
                families,
                unknown_reasons: allocation.unknown_reasons.into_iter().collect(),
            });
        }

        report.resident_readings = self.resident_readings;
        report.resident_readings.sort_by_key(|reading| {
            (
                reading.family,
                reading.count,
                reading.weight,
                reading.weight_unit,
            )
        });
        report.allocation_groups.sort_by_key(|allocation| {
            (
                allocation.kind,
                allocation.estimated_bytes,
                allocation.accounting,
                allocation.families.clone(),
                allocation.unknown_reasons.clone(),
            )
        });
        report
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AllocationAccounting, FamilyLifetime, ResidentWeightUnit, RetentionCensus, UnknownKind,
    };
    use std::sync::Arc;

    struct FileArena {
        _bytes: [u8; 32],
    }

    #[test]
    fn shared_allocations_are_deduplicated_and_unknowns_stay_explicit() {
        let shared = Arc::new(FileArena { _bytes: [0; 32] });
        let independent = Arc::new(FileArena { _bytes: [1; 32] });
        let conflict = Arc::new(FileArena { _bytes: [2; 32] });
        let mut census = RetentionCensus::new();
        let persistent = FamilyLifetime::Persistent;

        census.record_allocation(
            Arc::as_ref(&shared),
            "cache.alpha",
            persistent,
            "file-arena",
            32,
            AllocationAccounting::AlreadyBudgeted,
        );
        census.record_allocation(
            Arc::as_ref(&shared),
            "cache.beta",
            persistent,
            "file-arena",
            32,
            AllocationAccounting::AlreadyBudgeted,
        );
        census.record_allocation(
            Arc::as_ref(&independent),
            "cache.alpha",
            persistent,
            "file-arena",
            19,
            AllocationAccounting::OutsideBudget,
        );
        census.record_allocation(
            Arc::as_ref(&conflict),
            "cache.alpha",
            persistent,
            "file-arena",
            11,
            AllocationAccounting::OutsideBudget,
        );
        census.record_allocation(
            Arc::as_ref(&conflict),
            "cache.beta",
            persistent,
            "file-arena",
            13,
            AllocationAccounting::OutsideBudget,
        );
        census.record_allocation(
            Arc::as_ref(&conflict),
            "cache.beta",
            persistent,
            "file-arena",
            11,
            AllocationAccounting::AlreadyBudgeted,
        );
        census.record_unknown(
            "cache.alpha",
            persistent,
            UnknownKind::NativeBytes,
            "native payload size unavailable",
        );
        census.record_unknown(
            "cache.beta",
            persistent,
            UnknownKind::Coverage,
            "provider set incomplete",
        );
        census.record_unknown(
            "provider.transient",
            FamilyLifetime::ProviderOnly,
            UnknownKind::ActivePins,
            "active pin size unavailable",
        );
        census.record_resident_reading(
            "cache.alpha",
            persistent,
            3,
            96,
            ResidentWeightUnit::BytesEstimate,
        );
        census.record_resident_reading(
            "provider.transient",
            FamilyLifetime::ProviderOnly,
            2,
            2,
            ResidentWeightUnit::Entries,
        );

        let report = census.finish();
        assert_eq!(
            report.union.cache_owned_capacity_bytes, 19,
            "already-budgeted shared backing must not be counted as cache-owned"
        );
        assert_eq!(report.union.already_accounted_backing_bytes, 32);
        assert_eq!(report.union.known_bytes, 51);
        assert_eq!(report.families[0].family, "cache.alpha");
        assert_eq!(report.families[0].cache_owned_capacity_bytes, 19);
        assert_eq!(report.families[0].already_accounted_backing_bytes, 32);
        assert_eq!(report.families[1].family, "cache.beta");
        assert_eq!(report.families[1].already_accounted_backing_bytes, 32);
        assert!(report.families[0].unknown_reasons.iter().any(|reason| {
            reason.kind == UnknownKind::NativeBytes
                && reason.reason == "native payload size unavailable"
        }));
        assert!(report.families[1].unknown_reasons.iter().any(|reason| {
            reason.kind == UnknownKind::Coverage && reason.reason == "provider set incomplete"
        }));
        assert_eq!(
            report.families[2].lifetime,
            Some(FamilyLifetime::ProviderOnly)
        );
        assert_eq!(
            report.families[2].unknown_active_pins,
            vec!["active pin size unavailable"]
        );
        assert!(report.allocation_groups.iter().any(|group| {
            group.families == ["cache.alpha", "cache.beta"]
                && group.estimated_bytes.is_none()
                && group.accounting.is_none()
                && group.kind == Some("file-arena")
                && group.unknown_reasons.iter().any(|reason| {
                    reason.kind == UnknownKind::ConflictingObservation
                        && reason.reason == "allocation_size_disagreed"
                })
                && group.unknown_reasons.iter().any(|reason| {
                    reason.kind == UnknownKind::ConflictingObservation
                        && reason.reason == "allocation_accounting_disagreed"
                })
        }));
        assert_eq!(report.resident_readings.len(), 2);
        assert_eq!(
            report.resident_readings[0].weight_unit,
            ResidentWeightUnit::BytesEstimate
        );
        assert_eq!(
            report.resident_readings[1].weight_unit,
            ResidentWeightUnit::Entries
        );

        let pinned = Arc::new(FileArena { _bytes: [3; 32] });
        let weak = Arc::downgrade(&pinned);
        let mut pin_census = RetentionCensus::new();
        pin_census.record_arc_allocation(
            Arc::clone(&pinned),
            "cache.pinned",
            persistent,
            "file-arena",
            32,
            AllocationAccounting::AlreadyBudgeted,
        );
        drop(pinned);
        assert!(weak.upgrade().is_some(), "the census pins until finish");
        drop(pin_census.finish());
        assert!(
            weak.upgrade().is_none(),
            "finish releases the invocation pin"
        );
    }
}
