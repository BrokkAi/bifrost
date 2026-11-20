pub use super::configuration_kinds::{
    RustUnitConfiguration, RustUnitConfigurationFacts, RustUnitConfigurationKey,
};
use brokk_bifrost_analysis::analyzer::derivation_host::{self, AnalyzerDerivations};
use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_access::RustBlobActivity;
use brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::{
    RustSelectedUnitsPublication, RustUnitAvailability, rust_broad_file_units,
    rust_broad_placement_rows, rust_crate_name_units, rust_file_unit_availability, rust_file_units,
    rust_package_units, rust_selected_units_known, rust_unit_availability, rust_unit_dependents,
    rust_unit_file_activity, rust_unit_inputs, rust_unit_package_rows,
    rust_unit_placement_activity,
};
use brokk_bifrost_analysis::analyzer::{IAnalyzer, QueryReadIncomplete};
use brokk_bifrost_core::allocation_size::allocation_size;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::model::{Language, ProjectFile};
use brokk_bifrost_core::analyzer::rust_facts::{
    RustModuleRouteFacts, encode_rust_cfg_condition, encode_rust_visibility,
};
use brokk_bifrost_core::attribution::{self, CoverageClass};
use brokk_bifrost_core::gitblob::BlobKey;
use brokk_bifrost_core::hash::{
    HashMap, HashSet, allocated_table_slot_bytes, allocated_vec_slot_bytes,
};
use brokk_bifrost_core::retention_budget::RetainedBytes;
use brokk_bifrost_rust::cargo_manifest::normalize_crate_name;
use brokk_bifrost_rust::cargo_routes::{
    RustCargoDependencyKind, RustCargoRouteIndex, RustCargoRouteSummaryRow, RustInactivePlacements,
    RustPlacementState, SelectedRustRoutePathFacts,
};
use brokk_bifrost_rust::crate_naming::RustSelectedCargoNaming;
use brokk_bifrost_semantic::analyzer::semantic::derivation::Demanded;
use brokk_bifrost_semantic::analyzer::semantic::derivation::{
    Computed, DerivationAuthority, DerivationFrame, DerivationKind, DerivationKindId,
    DerivationQuestion, DerivationRevision, IncompleteReason, ReuseValidity, UnavailableCause,
    Verification,
};
use git2::Oid;
use std::path::PathBuf;
use std::sync::Arc;

/// A selected unit identity. Coverage belongs to the question that selected
/// it; each consumer re-reads this unit's availability at its own binding.
#[derive(Debug, Clone)]
pub struct SelectedRustUnit {
    key: [u8; 32],
}
impl SelectedRustUnit {
    fn mint(key: [u8; 32]) -> Self {
        Self { key }
    }
    fn replayed(key: [u8; 32]) -> Self {
        Self::mint(key)
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn minted_by_test_fixture(key: [u8; 32]) -> Self {
        Self::mint(key)
    }
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

impl PartialEq for SelectedRustUnit {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for SelectedRustUnit {}

impl std::hash::Hash for SelectedRustUnit {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl RetainedBytes for SelectedRustUnit {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

/// The raw rows of a units question, and the answer that names them as
/// selected units once the question's completeness is known.
trait UnitRows {
    type Selected: HashAnswer;
    fn select(self) -> Self::Selected;
}

trait HashAnswer {
    fn append(&self, hash: &mut CanonicalHasher);
}

impl UnitRows for Vec<[u8; 32]> {
    type Selected = Vec<SelectedRustUnit>;
    fn select(self) -> Self::Selected {
        self.into_iter().map(SelectedRustUnit::mint).collect()
    }
}

impl UnitRows for Vec<([u8; 32], String)> {
    type Selected = Vec<(SelectedRustUnit, String)>;
    fn select(self) -> Self::Selected {
        self.into_iter()
            .map(|(key, kind)| (SelectedRustUnit::mint(key), kind))
            .collect()
    }
}

impl UnitRows for Vec<([u8; 32], u32)> {
    type Selected = Vec<(SelectedRustUnit, u32)>;
    fn select(self) -> Self::Selected {
        self.into_iter()
            .map(|(key, ordinal)| (SelectedRustUnit::mint(key), ordinal))
            .collect()
    }
}

impl UnitRows for Vec<([u8; 32], String, String)> {
    type Selected = Vec<(SelectedRustUnit, String, String)>;
    fn select(self) -> Self::Selected {
        self.into_iter()
            .map(|(key, kind, root)| (SelectedRustUnit::mint(key), kind, root))
            .collect()
    }
}

impl HashAnswer for Vec<SelectedRustUnit> {
    fn append(&self, hash: &mut CanonicalHasher) {
        for unit in self {
            hash.value(unit.key());
        }
    }
}

impl HashAnswer for Vec<(SelectedRustUnit, String)> {
    fn append(&self, hash: &mut CanonicalHasher) {
        for (unit, kind) in self {
            hash.value(unit.key());
            hash.value(kind.as_bytes());
        }
    }
}

impl HashAnswer for Vec<(SelectedRustUnit, u32)> {
    fn append(&self, hash: &mut CanonicalHasher) {
        for (unit, ordinal) in self {
            hash.value(unit.key());
            hash.value(&ordinal.to_be_bytes());
        }
    }
}

impl HashAnswer for Vec<(SelectedRustUnit, String, String)> {
    fn append(&self, hash: &mut CanonicalHasher) {
        for (unit, kind, root) in self {
            hash.value(unit.key());
            hash.value(kind.as_bytes());
            hash.value(root.as_bytes());
        }
    }
}

/// Records the one incompleteness gap a partial route or package answer
/// carries: the units whose evidence could not be proven complete. A request
/// memo that holds the answer replays the reason on a hit, so a consumer served
/// from the memo still records it.
pub fn record_route_evidence_gap(analyzer: &dyn IAnalyzer, units: &[[u8; 32]]) {
    analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
        brokk_bifrost_core::bounded_output::bounded_diagnostic_items(
            format_args!("{ROUTE_EVIDENCE_GAP} {units:02x?}"),
            format_args!("{ROUTE_EVIDENCE_GAP}; detail_kind=UnitKey"),
            units.iter(),
        )
        .into(),
    ));
}

/// The gap text for a file whose test classification an undecided `cfg` leaves
/// open: no build proves it production, and an undecided route may.
pub fn uncertain_test_verdict_gap_text(file: &ProjectFile) -> String {
    format!(
        "Rust test classification is undecided for a file an undecided cfg route may compile: {:?}",
        file.rel_path()
    )
}

/// The text a route evidence gap starts with.
const ROUTE_EVIDENCE_GAP: &str = "Rust route evidence is incomplete for units";

/// The text a gap for a file placed only under an inactive or unknown `cfg`
/// starts with.
const INACTIVE_PLACEMENT_GAP: &str =
    "Rust route evidence is incomplete for a file placed only under an inactive or unknown cfg:";

pub fn inactive_placement_gap_text(file: &ProjectFile) -> String {
    format!("{INACTIVE_PLACEMENT_GAP} {:?}", file.rel_path())
}

/// Records that the routes of `file` are incomplete because no selected build
/// compiles it. Like [`record_route_evidence_gap`], it runs inside the
/// memoized build, so a hit replays it.
pub fn record_inactive_placement_gap(analyzer: &dyn IAnalyzer, file: &ProjectFile) {
    analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
        inactive_placement_gap_text(file).into(),
    ));
}

/// The route evidence gap multiset in canonical presentation order. Keep every
/// recorded string and its multiplicity; capture order is not answer identity.
pub fn route_evidence_gaps(reasons: &[QueryReadIncomplete]) -> Vec<String> {
    let mut gaps = reasons
        .iter()
        .filter_map(|reason| match reason {
            QueryReadIncomplete::SemanticEvidenceGap(text)
                if text.starts_with(ROUTE_EVIDENCE_GAP)
                    || text.starts_with(INACTIVE_PLACEMENT_GAP) =>
            {
                Some(text.to_string())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    gaps.sort_by_cached_key(|text| {
        QueryReadIncomplete::SemanticEvidenceGap(text.clone().into()).answer_order_key()
    });
    gaps
}

/// Render the complete gap multiset through the same canonical boundary on
/// cold computation and warm replay. Never format raw capture order.
pub(super) fn render_route_evidence_gaps(reasons: &[QueryReadIncomplete]) -> Option<String> {
    let gaps = route_evidence_gaps(reasons);
    (!gaps.is_empty()).then(|| format!("{gaps:?}"))
}

fn record_route_store_error(
    error: impl Into<brokk_bifrost_analysis::analyzer::store::StoreError>,
) -> String {
    let error = error.into();
    let message = error.to_string();
    if !error.is_cancelled() {
        derivation_host::with_current_analyzer(|analyzer| analyzer.record_query_failure(error));
    }
    message
}

/// The answer to a units question, naming every unit in it as selected.
fn read<T: UnitRows>(
    family: &'static str,
    complete: bool,
    f: impl FnOnce(&brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventory<'_>, &brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId) -> Result<T, String>,
) -> Computed<T::Selected> {
    let _scope = attribution::enter_scope(family, CoverageClass::RecomputeOnCurrency);
    match derivation_host::with_bound_inventory(|i| {
        let s = derivation_host::selected_rust_snapshot(i)?;
        f(i, &s)
    }) {
        Ok(rows) => Computed::Available {
            value: rows.select(),
            complete,
            validity: ReuseValidity::Reusable,
            reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
        },
        Err(e) => Computed::Unavailable(UnavailableCause::Failed(e.into())),
    }
}
#[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
fn unit_intentionally_unavailable(unit: &[u8; 32]) -> Result<bool, String> {
    let state = derivation_host::with_bound_inventory(|i| {
        let snapshot = derivation_host::selected_rust_snapshot(i)?;
        rust_unit_availability(i.connection(), &snapshot, unit).map_err(record_route_store_error)
    })?;
    match state {
        Some(RustUnitAvailability::IntentionallyUnavailable { cause, .. }) => {
            derivation_host::with_current_analyzer(|a| {
                a.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(format!("Rust route evidence incomplete: unit {unit:02x?}: target_root_unavailable {cause:?}").into()))
            });
            Ok(true)
        }
        // A stale unit can be an unavailable target whose state this head has
        // not decided. Answering it as an ordinary unit could report a complete
        // absence, so the derivation fails closed.
        Some(RustUnitAvailability::Stale) => Err(format!(
            "stale selected Rust unit {unit:02x?}: derivation or reconcile pending"
        )),
        Some(state) => {
            state
                .require_published_or_stale(unit)
                .map_err(record_route_store_error)?;
            Ok(false)
        }
        None => Ok(false),
    }
}

fn availability_projection(
    states: Vec<([u8; 32], RustUnitAvailability)>,
) -> Result<([u8; 32], bool), String> {
    let mut complete = true;
    let mut digest = CanonicalHasher::new(b"rust-unit-availability:v1");
    for (unit, state) in states {
        state
            .require_published_or_stale(&unit)
            .map_err(record_route_store_error)?;
        digest.value(&unit);
        match state {
            RustUnitAvailability::Published {
                input,
                complete: own,
            } => {
                digest.value(&[0]);
                digest.value(&input);
                digest.value(&[u8::from(own)]);
                complete &= own;
            }
            RustUnitAvailability::IntentionallyUnavailable { cause, evidence } => {
                digest.value(&[1]);
                digest.value(&evidence);
                complete = false;
                derivation_host::with_current_analyzer(|a| {
                    a.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(format!("Rust route evidence incomplete: unit {unit:02x?}: target_root_unavailable {cause:?}").into()))
                });
            }
            RustUnitAvailability::Unpublished => {
                unreachable!("rejected by require_published_or_stale")
            }
            // Stale between an upgrade and reconcile: unknown, so incomplete, and
            // the tag keeps the projection distinct from every current state.
            RustUnitAvailability::Stale => {
                digest.value(&[3]);
                complete = false;
            }
        }
    }
    Ok::<_, String>((digest.finish(), complete))
}

/// Local coverage has its own projection so a changed gap or claim invalidates
/// replay even when the selected healthy unit keys are unchanged.
pub struct RustFileAvailability;
impl DerivationKind for RustFileAvailability {
    type Key = String;
    type Output = [u8; 32];
    const ID: DerivationKindId = DerivationKindId("derivation:rust_file_availability:v1");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            false,
            true,
            false,
        );
    const STRATUM: u16 = 0;
    const VERIFY: Verification = Verification::Recompute;
    const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
    fn question(path: &String) -> DerivationQuestion {
        question(None, Some(path.clone().into_boxed_str()), None)
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<String> {
        (q.language == Some(Language::Rust) && q.subject.is_none() && q.name.is_none())
            .then(|| q.rel_path.as_deref().map(str::to_owned))
            .flatten()
    }
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        _: &mut DerivationFrame<'_, R, A>,
        path: &String,
    ) -> Computed<[u8; 32]> {
        let _scope =
            attribution::enter_scope("rust_file_availability", CoverageClass::RecomputeOnCurrency);
        let result = derivation_host::with_bound_inventory(|i| {
            let s = derivation_host::selected_rust_snapshot(i)?;
            let states = rust_file_unit_availability(i.connection(), &s, path)
                .map_err(record_route_store_error)?;
            availability_projection(states)
        });
        match result {
            Ok((value, complete)) => Computed::Available {
                value,
                complete,
                validity: ReuseValidity::Reusable,
                reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
            },
            Err(error) => Computed::Unavailable(UnavailableCause::Failed(error.into())),
        }
    }
    fn output_projection(value: &[u8; 32], hash: &mut CanonicalHasher) {
        hash.value(value);
    }
}

pub struct RustNameAvailability;
impl DerivationKind for RustNameAvailability {
    type Key = String;
    type Output = [u8; 32];
    const ID: DerivationKindId = DerivationKindId("derivation:rust_name_availability:v1");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            false,
            false,
            true,
        );
    const STRATUM: u16 = 0;
    const VERIFY: Verification = Verification::Recompute;
    const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
    fn question(name: &Self::Key) -> DerivationQuestion {
        question(None, None, Some(name.clone().into_boxed_str()))
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<Self::Key> {
        (q.language == Some(Language::Rust) && q.subject.is_none() && q.rel_path.is_none())
            .then(|| q.name.as_deref().map(str::to_owned))
            .flatten()
    }
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        _: &mut DerivationFrame<'_, R, A>,
        name: &Self::Key,
    ) -> Computed<Self::Output> {
        let _scope =
            attribution::enter_scope("rust_name_availability", CoverageClass::RecomputeOnCurrency);
        let result = derivation_host::with_bound_inventory(|i| {
            let s = derivation_host::selected_rust_snapshot(i)?;
            let states=brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_name_unit_availability(i.connection(),&s,name).map_err(record_route_store_error)?;
            availability_projection(states)
        });
        match result {
            Ok((value, complete)) => Computed::Available {
                value,
                complete,
                validity: ReuseValidity::Reusable,
                reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
            },
            Err(error) => Computed::Unavailable(UnavailableCause::Failed(error.into())),
        }
    }
    fn output_projection(value: &Self::Output, hash: &mut CanonicalHasher) {
        hash.value(value);
    }
}

fn project_answer<T: HashAnswer>(family: &'static str, value: &T, h: &mut CanonicalHasher) {
    let mut answer = CanonicalHasher::new(b"rust-route-listing-answer:v2");
    answer.value(family.as_bytes());
    value.append(&mut answer);
    h.value(&answer.finish());
}

/// Whether the request that demanded this computation is still live.
fn route_build_progress() -> impl Fn() -> bool {
    let cancellation = derivation_host::with_current_analyzer(|a| a.active_query_cancellation());
    move || {
        cancellation
            .as_ref()
            .is_none_or(|token| !token.is_cancelled())
    }
}

/// The route index over `files`, answering path probes and package names from
/// the selection: a candidate exists when it is one of `files`, and the
/// selection's manifests name the packages. Nothing is read from the
/// filesystem, so the answer is a function of the inputs the demanding kind
/// binds. Also returns the module candidates the selection cannot prove absent.
/// `Unavailable(Cancelled)` when the request is cancelled.
fn selected_route_index(
    files: &[ProjectFile],
    facts: &HashMap<ProjectFile, RustModuleRouteFacts>,
    rows: &[RustCargoRouteSummaryRow],
    records: &[(PathBuf, String, PathBuf)],
    inactive: &RustInactivePlacements,
) -> Result<(RustCargoRouteIndex, Vec<ProjectFile>), UnavailableCause> {
    let naming = RustSelectedCargoNaming::from_naming_records(
        files.iter().map(|file| file.rel_path().to_path_buf()),
        records,
    );
    let selected = files.iter().cloned().collect::<HashSet<_>>();
    // A file the selection mounts that is not a member of this unit: the
    // persisted unit does not know it, and a declaration naming it is unproven.
    // A failed lookup proves nothing, so it counts as held.
    let held_by_selection = |candidate: &ProjectFile| {
        let path =
            brokk_bifrost_core::path_utils::workspace_relative_slash_path(candidate.rel_path());
        derivation_host::with_bound_inventory(|i| i.mount_record_for_path("rust", &path))
            .map_or(true, |mount| mount.is_some())
    };
    let paths = SelectedRustRoutePathFacts::new(&selected, &naming, &held_by_selection);
    let index = RustCargoRouteIndex::build_from_summary_rows_with_path_facts(
        files,
        facts,
        rows,
        &paths,
        inactive,
        &route_build_progress(),
    )
    .ok_or(UnavailableCause::Cancelled)?;
    Ok((index, paths.unproven_candidates()))
}

fn question(
    subject: Option<[u8; 32]>,
    rel_path: Option<Box<str>>,
    name: Option<Box<str>>,
) -> DerivationQuestion {
    DerivationQuestion {
        language: Some(Language::Rust),
        subject,
        rel_path,
        name,
    }
}

/// Whether every selected live Rust crate has a publishable summary. The
/// questions about which units hold a file, a package or a crate name, and
/// which units depend on a unit, are exhaustive only then: a crate without
/// one has unknown membership, so the answer is incomplete.
/// One keyed check per binding, shared by every question at that binding.
pub struct RustSelectedUnitsKnown;
impl DerivationKind for RustSelectedUnitsKnown {
    type Key = u8;
    type Output = [u8; 32];
    const ID: DerivationKindId = DerivationKindId("derivation:rust_selected_units_known:v1");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            false,
            false,
            false,
        );
    const STRATUM: u16 = 0;
    const VERIFY: Verification = Verification::Recompute;
    const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
    fn question(_: &Self::Key) -> DerivationQuestion {
        question(None, None, None)
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<Self::Key> {
        (q.language == Some(Language::Rust)
            && q.subject.is_none()
            && q.rel_path.is_none()
            && q.name.is_none())
        .then_some(0)
    }
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        _: &mut DerivationFrame<'_, R, A>,
        _: &Self::Key,
    ) -> Computed<Self::Output> {
        let _scope = attribution::enter_scope(
            "rust_selected_units_known",
            CoverageClass::RecomputeOnCurrency,
        );
        let known = derivation_host::with_bound_inventory(|i| -> Result<_, String> {
            let s = derivation_host::selected_rust_snapshot(i)?;
            let units =
                rust_selected_units_known(i.connection(), &s).map_err(record_route_store_error)?;
            // An uncertified listing may have hidden any manifest or source
            // file, so even an empty or fully published unit set is not known
            // to be every unit.
            let listing = AnalyzerStore::rust_source_listing_complete_on_connection(
                i.connection(),
                &s,
                brokk_bifrost_analysis::analyzer::store::rust_source_listing_derivation_identity(),
            )
            .map_err(record_route_store_error)?;
            Ok((units, listing))
        });
        match known {
            Ok((RustSelectedUnitsPublication::Published { partial }, listing)) => {
                if !listing {
                    derivation_host::with_current_analyzer(|a| {
                        a.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                            "Rust source listing certificate is incomplete".into(),
                        ))
                    });
                }
                if !partial.is_empty() {
                    derivation_host::with_current_analyzer(|a| {
                        a.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                            brokk_bifrost_core::bounded_output::bounded_diagnostic_items(format_args!("selected Rust crate membership is incomplete: {partial:02x?}"), format_args!("selected Rust crate membership is incomplete; detail_kind=UnitKey"), partial.iter())
                                .into(),
                        ))
                    });
                }
                let mut hash = CanonicalHasher::new(b"derivation:rust_selected_units_known:v1");
                for unit in &partial {
                    hash.value(unit);
                }
                hash.value(&[u8::from(listing)]);
                Computed::Available {
                    value: hash.finish(),
                    complete: listing && partial.is_empty(),
                    validity: ReuseValidity::Reusable,
                    reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
                }
            }
            Ok((RustSelectedUnitsPublication::Unpublished(units), _)) => {
                Computed::Unavailable(UnavailableCause::Failed(
                    format!("unpublished or stale selected Rust units: {units:02x?}").into(),
                ))
            }
            Err(error) => Computed::Unavailable(UnavailableCause::Failed(error.into())),
        }
    }
    fn output_projection(v: &Self::Output, h: &mut CanonicalHasher) {
        h.value(v);
    }
}

fn selected_units_known<R: DerivationRevision, A: DerivationAuthority>(
    frame: &mut DerivationFrame<'_, R, A>,
) -> Result<bool, UnavailableCause> {
    match frame.demand::<RustSelectedUnitsKnown>(&0) {
        Demanded::Available { complete, .. } => Ok(complete),
        Demanded::Unavailable(cause) => Err(cause),
    }
}

type UnitMembers = (
    Vec<brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::RustSummaryPackageRow>,
    Vec<(ProjectFile, Option<Oid>)>,
    RustInactivePlacements,
);

/// The persisted unit's members, each with the content the request's selection
/// mounts at its path: an overlay's content for an edited file, `None` for a
/// masked or removed one (never the revision's blob). Membership is the
/// persisted unit's; a path the unit does not know does not join it.
#[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
fn unit_members(unit: &[u8; 32]) -> Result<UnitMembers, String> {
    let root = derivation_host::with_current_analyzer(|a| a.project().root().to_path_buf());
    derivation_host::with_bound_inventory(|i| {
        let snapshot = derivation_host::selected_rust_snapshot(i)?;
        let package =
            AnalyzerStore::rust_selected_package_rows_for_unit(i.connection(), &snapshot, unit)
                .map_err(record_route_store_error)?;
        let placements = rust_broad_placement_rows(i.connection(), &snapshot, unit)
            .map_err(record_route_store_error)?;
        // Files no selected build is proved to compile, split by what the
        // activation proves. The activity is the store's one definition
        // (`rust_file_activity.sql`); a file without a stored placement is not
        // listed and keeps its existing treatment.
        let mut not_active = RustInactivePlacements::default();
        for (path, activity) in rust_unit_file_activity(i.connection(), &snapshot, unit)
            .map_err(record_route_store_error)?
        {
            match activity {
                RustBlobActivity::Active => {}
                RustBlobActivity::Inactive => {
                    not_active
                        .proven_inactive
                        .insert(ProjectFile::new(root.clone(), path));
                }
                RustBlobActivity::Unknown => {
                    not_active
                        .undecided
                        .insert(ProjectFile::new(root.clone(), path));
                }
            }
        }
        for (path, module_path, activity) in
            rust_unit_placement_activity(i.connection(), &snapshot, unit)
                .map_err(record_route_store_error)?
        {
            not_active
                .placements
                .entry(ProjectFile::new(root.clone(), path))
                .or_default()
                .push((
                    module_path,
                    match activity {
                        RustBlobActivity::Active => RustPlacementState::Active,
                        RustBlobActivity::Inactive => RustPlacementState::Inactive,
                        RustBlobActivity::Unknown => RustPlacementState::Undecided,
                    },
                ));
        }
        let mut members = package
            .iter()
            .map(|r| {
                Ok((
                    ProjectFile::new(root.clone(), &r.rel_path),
                    r.blob_oid
                        .as_deref()
                        .map(Oid::from_str)
                        .transpose()
                        .map_err(record_route_store_error)?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        for (path, _, _, _, oid) in placements {
            members.push((
                ProjectFile::new(root.clone(), path),
                oid.map(|oid| Oid::from_str(&oid))
                    .transpose()
                    .map_err(record_route_store_error)?,
            ));
        }
        members.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        members.dedup();
        Ok((package, members, not_active))
    })
}

pub struct RustUnitNaming;
impl DerivationKind for RustUnitNaming {
    type Key = [u8; 32];
    type Output = Vec<(PathBuf, String, PathBuf)>;
    const ID: DerivationKindId = DerivationKindId("derivation:rust_unit_naming:v1");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            true,
            false,
            false,
        );
    const STRATUM: u16 = 0;
    const VERIFY: Verification = Verification::Recompute;
    const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
    fn question(k: &Self::Key) -> DerivationQuestion {
        RustUnitInputs::question(k)
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<Self::Key> {
        RustUnitInputs::key_from_question(q)
    }
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        _: &mut DerivationFrame<'_, R, A>,
        unit: &Self::Key,
    ) -> Computed<Self::Output> {
        let _scope =
            attribution::enter_scope("rust_unit_naming", CoverageClass::RecomputeOnCurrency);
        match unit_intentionally_unavailable(unit) {
            Ok(true) => {
                return Computed::Available {
                    value: Vec::new(),
                    complete: false,
                    validity: ReuseValidity::Reusable,
                    reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
                };
            }
            Ok(false) => {}
            Err(error) => return Computed::Unavailable(UnavailableCause::Failed(error.into())),
        }
        let result = (|| {
            let (_, members, _) = unit_members(unit)?;
            let mut paths = members
                .iter()
                .flat_map(|(file, _)| {
                    file.rel_path()
                        .parent()
                        .into_iter()
                        .flat_map(|p| p.ancestors())
                        .map(|p| {
                            brokk_bifrost_core::path_utils::workspace_relative_slash_path(
                                &p.join("Cargo.toml"),
                            )
                        })
                })
                .collect::<Vec<_>>();
            paths.sort_unstable();
            paths.dedup();
            let (mounts, _, unreadable) = derivation_host::with_bound_inventory(|i| {
                let snapshot = derivation_host::selected_rust_snapshot(i)?;
                AnalyzerStore::rust_selected_manifest_mounts_at_paths(
                    i.connection(),
                    &snapshot,
                    &paths,
                )
                .map_err(record_route_store_error)
            })?;
            let mut records = mounts
                .into_iter()
                .filter_map(|m| {
                    m.facts
                        .package
                        .map(|p| (m.relative_path, p.library_name, p.library_path))
                })
                .collect::<Vec<_>>();
            records.sort_unstable();
            Ok::<_, String>((records, unreadable))
        })();
        match result {
            Ok((value, unreadable)) => {
                // An unreadable manifest may name a library that the records
                // omit, so the naming is a partial answer.
                if !unreadable.is_empty() {
                    derivation_host::with_current_analyzer(|a| {
                        a.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                            brokk_bifrost_core::bounded_output::bounded_diagnostic_items(format_args!("Rust unit {unit:02x?} has unreadable manifests: {unreadable:?}"), format_args!("Rust unit {unit:02x?} has unreadable manifests; detail_kind=Manifest"), unreadable.iter())
                            .into(),
                        ))
                    });
                }
                Computed::Available {
                    value,
                    complete: unreadable.is_empty(),
                    validity: ReuseValidity::Reusable,
                    reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
                }
            }
            Err(e) => Computed::Unavailable(UnavailableCause::Failed(e.into())),
        }
    }
    fn output_projection(v: &Self::Output, h: &mut CanonicalHasher) {
        for (path, name, library) in v {
            h.value(&path_bytes(path));
            h.value(name.as_bytes());
            h.value(&path_bytes(library));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustDependencyPackageIdentity(pub Result<String, String>);

impl RetainedBytes for RustDependencyPackageIdentity {
    fn retained_bytes(&self) -> usize {
        match &self.0 {
            Ok(value) | Err(value) => {
                std::mem::size_of::<Self>() + allocation_size(value.capacity())
            }
        }
    }
}

pub struct RustUnitDependencyIdentities;
impl DerivationKind for RustUnitDependencyIdentities {
    type Key = [u8; 32];
    type Output = Vec<(PathBuf, String, RustDependencyPackageIdentity)>;
    const ID: DerivationKindId = DerivationKindId("derivation:rust_unit_dependency_identities:v1");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            true,
            false,
            false,
        );
    const STRATUM: u16 = 0;
    const VERIFY: Verification = Verification::Recompute;
    const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
    fn question(k: &Self::Key) -> DerivationQuestion {
        RustUnitInputs::question(k)
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<Self::Key> {
        RustUnitInputs::key_from_question(q)
    }
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        _: &mut DerivationFrame<'_, R, A>,
        unit: &Self::Key,
    ) -> Computed<Self::Output> {
        let _scope = attribution::enter_scope(
            "rust_unit_dependency_identities",
            CoverageClass::RecomputeOnCurrency,
        );
        let result = (|| {
            let manifest = derivation_host::with_bound_inventory(|inventory| {
                let snapshot = derivation_host::selected_rust_snapshot(inventory)?;
                let rows = AnalyzerStore::rust_summary_cargo_route_rows_for_unit(
                    inventory.connection(),
                    &snapshot,
                    unit,
                )
                .map_err(record_route_store_error)?;
                let paths = rows
                    .into_iter()
                    .filter_map(|row| row.manifest_rel_path)
                    .collect::<HashSet<_>>();
                if paths.len() != 1 {
                    return Err(format!(
                        "Rust unit has no unique owning manifest: {paths:?}"
                    ));
                }
                Ok::<_, String>(PathBuf::from(
                    paths.into_iter().next().expect("one manifest"),
                ))
            })?;
            let mut paths = manifest
                .parent()
                .expect("manifest directory")
                .ancestors()
                .map(|parent| {
                    brokk_bifrost_core::path_utils::workspace_relative_slash_path(
                        &parent.join("Cargo.toml"),
                    )
                })
                .collect::<Vec<_>>();
            paths.sort_unstable();
            paths.dedup();
            let (mounts, _, unreadable) = derivation_host::with_bound_inventory(|i| {
                let snapshot = derivation_host::selected_rust_snapshot(i)?;
                AnalyzerStore::rust_selected_manifest_mounts_at_paths(
                    i.connection(),
                    &snapshot,
                    &paths,
                )
                .map_err(record_route_store_error)
            })?;
            // Every configuration level from the owning manifest's directory up,
            // which includes the workspace root's levels.
            let configuration_paths = manifest
                .parent()
                .expect("manifest directory")
                .ancestors()
                .flat_map(|parent| {
                    ["config.toml", "config"].map(|name| {
                        brokk_bifrost_core::path_utils::workspace_relative_slash_path(
                            &parent.join(".cargo").join(name),
                        )
                    })
                })
                .collect::<Vec<_>>();
            let configuration = derivation_host::with_bound_inventory(|i| {
                let snapshot = derivation_host::selected_rust_snapshot(i)?;
                AnalyzerStore::rust_selected_cargo_configuration_at_paths(
                    i.connection(),
                    &snapshot,
                    &configuration_paths,
                )
                .map_err(record_route_store_error)?
                .map_err(|errors| format!("Unreadable selected Cargo configuration: {errors:?}"))
            })?;
            let documents = mounts
                .iter()
                .map(|mount| {
                    (
                        mount
                            .relative_path
                            .parent()
                            .expect("manifest has a directory")
                            .to_path_buf(),
                        mount.document().clone(),
                    )
                })
                .collect::<HashMap<_, _>>();
            let mut records = Vec::new();
            for mount in mounts
                .iter()
                .filter(|mount| mount.relative_path == manifest)
            {
                // Preserve package boundaries even with no dependencies.
                records.push((
                    mount.relative_path.clone(),
                    String::new(),
                    RustDependencyPackageIdentity(Err("package boundary".to_owned())),
                ));
                for dependency in &mount.facts.dependencies {
                    let table = match dependency.kind {
                        brokk_bifrost_rust::selected_context::RustCargoDependencyKind::Normal => "dependencies",
                        brokk_bifrost_rust::selected_context::RustCargoDependencyKind::Development => "dev-dependencies",
                        brokk_bifrost_rust::selected_context::RustCargoDependencyKind::Build => "build-dependencies",
                    };
                    let raw = mount
                        .document()
                        .get(table)
                        .and_then(|table| table.get(&dependency.manifest_name))
                        .expect("dependency fact retains its source value");
                    let directory = mount
                        .relative_path
                        .parent()
                        .expect("manifest has directory");
                    let package = brokk_bifrost_rust::cargo_routes::cargo_dependency_value(
                        std::path::Path::new(""), directory, mount.document(),
                        &dependency.manifest_name, raw, &documents,
                    ).ok_or_else(|| "dependency value or inherited workspace identity is unavailable".to_owned()).and_then(|(value, _)| {
                        let package = value.get("package").and_then(|value| value.as_str())
                            .unwrap_or(&dependency.manifest_name);
                        if package == "log" {
                            // Only a registry requirement without a source override can
                            // establish the external logging boundary.
                            let requirement = value.as_str().or_else(|| value.get("version").and_then(|v| v.as_str()));
                            if requirement.is_none() || value.get("path").is_some() || value.get("git").is_some()
                                || value.get("registry").is_some() || value.get("registry-index").is_some() {
                                return Err("log dependency is not an unmodified default-registry requirement".to_owned());
                            }
                            let root = brokk_bifrost_rust::cargo_routes::cargo_workspace_manifest_directory(
                                std::path::Path::new(""), directory, mount.document(), &documents,
                            ).ok_or_else(|| "owning workspace manifest is unavailable".to_owned())?;
                            let root_manifest = documents.get(&root).ok_or_else(|| "workspace manifest document is unavailable".to_owned())?;
                            let patched = root_manifest.get("patch").and_then(|v| v.as_table())
                                .is_some_and(|sources| sources.values().any(|entries| entries.as_table().is_some_and(|entries|
                                    entries.iter().any(|(name, entry)| name == "log" || entry.get("package").and_then(|v| v.as_str()) == Some("log"))
                                )));
                            let replaced = root_manifest.get("replace").and_then(|v| v.as_table())
                                .is_some_and(|entries| entries.iter().any(|(name, entry)|
                                    name == "log" || name.strip_prefix("log:").is_some()
                                    || entry.get("package").and_then(|v| v.as_str()) == Some("log")));
                            // Cargo reads configuration from the directory it runs in, which may
                            // be the member, so every level from the member up must preserve it.
                            if patched { return Err("log package is patched".to_owned()); }
                            if replaced { return Err("log package is replaced".to_owned()); }
                            if !configuration.preserves_registry_package(directory, "log") { return Err("log package is config-overridden".to_owned()); }
                        }
                        Ok(package.to_owned())
                    });
                    records.push((
                        mount.relative_path.clone(),
                        dependency.exposed_name.clone(),
                        RustDependencyPackageIdentity(package),
                    ));
                }
            }
            records.sort_unstable();
            Ok::<_, String>((records, unreadable))
        })();
        match result {
            Ok((value, unreadable)) => {
                // An unreadable selected manifest may change dependency identity,
                // so omitted records cannot establish a complete answer.
                if !unreadable.is_empty() {
                    derivation_host::with_current_analyzer(|a| {
                        a.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                            brokk_bifrost_core::bounded_output::bounded_diagnostic_items(format_args!("Rust unit {unit:02x?} has unreadable manifests: {unreadable:?}"), format_args!("Rust unit {unit:02x?} has unreadable manifests; detail_kind=Manifest"), unreadable.iter())
                            .into(),
                        ))
                    });
                }
                Computed::Available {
                    value,
                    complete: unreadable.is_empty(),
                    validity: ReuseValidity::Reusable,
                    reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
                }
            }
            Err(e) => Computed::Unavailable(UnavailableCause::Failed(e.into())),
        }
    }
    fn output_projection(v: &Self::Output, h: &mut CanonicalHasher) {
        for (path, name, library) in v {
            h.value(&path_bytes(path));
            h.value(name.as_bytes());
            match &library.0 {
                Ok(package) => {
                    h.value(b"package");
                    h.value(package.as_bytes());
                }
                Err(reason) => {
                    h.value(b"refusal");
                    h.value(reason.as_bytes());
                }
            }
        }
    }
}

pub struct RustUnitDependents;
pub struct RustUnitInputs;
// Each computation or new-binding verification performs two keyed per-unit
// reads and hashes their temporary row buffers. Only the content token remains.
impl DerivationKind for RustUnitInputs {
    type Key = [u8; 32];
    type Output = [u8; 32];
    const ID: DerivationKindId = DerivationKindId("derivation:rust_unit_inputs:v3");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            true,
            false,
            false,
        );
    const STRATUM: u16 = 0;
    const VERIFY: Verification = Verification::Recompute;
    const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
    fn question(k: &Self::Key) -> DerivationQuestion {
        question(Some(*k), None, None)
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<Self::Key> {
        (q.language == Some(Language::Rust) && q.rel_path.is_none() && q.name.is_none())
            .then_some(q.subject)
            .flatten()
    }
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        _: &mut DerivationFrame<'_, R, A>,
        k: &Self::Key,
    ) -> Computed<Self::Output> {
        let _scope =
            attribution::enter_scope("rust_unit_inputs", CoverageClass::RecomputeOnCurrency);
        if let Err(error) = unit_intentionally_unavailable(k) {
            return Computed::Unavailable(UnavailableCause::Failed(error.into()));
        }
        let result = derivation_host::with_bound_inventory(|i| {
            let s = derivation_host::selected_rust_snapshot(i)?;
            rust_unit_inputs(i.connection(), &s, k).map_err(record_route_store_error)
        });
        match result {
            Ok(Some((value, complete))) => {
                if !complete {
                    derivation_host::with_current_analyzer(|a| {
                        a.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                            format!("Rust unit {k:02x?} has incomplete inventory").into(),
                        ))
                    });
                }
                Computed::Available {
                    value,
                    complete,
                    validity: ReuseValidity::Reusable,
                    reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
                }
            }
            Ok(None) => {
                let mut h = CanonicalHasher::new(b"derivation:rust_unit_inputs:absent:v3");
                h.value(k);
                Computed::Available {
                    value: h.finish(),
                    complete: true,
                    validity: ReuseValidity::Reusable,
                    reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
                }
            }
            Err(error) => Computed::Unavailable(UnavailableCause::Failed(error.into())),
        }
    }
    fn output_projection(v: &Self::Output, h: &mut CanonicalHasher) {
        h.value(v);
    }
}
impl DerivationKind for RustUnitDependents {
    type Key = [u8; 32];
    type Output = Vec<(SelectedRustUnit, String)>;
    const ID: DerivationKindId = DerivationKindId("derivation:rust_unit_dependents:v1");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            true,
            false,
            false,
        );
    const STRATUM: u16 = 1;
    const VERIFY: Verification = Verification::Recompute;
    const CHILDREN: &'static [(DerivationKindId, u16)] = &[(RustSelectedUnitsKnown::ID, 0)];
    fn question(k: &Self::Key) -> DerivationQuestion {
        question(Some(*k), None, None)
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<Self::Key> {
        (q.language == Some(Language::Rust) && q.rel_path.is_none() && q.name.is_none())
            .then_some(q.subject)
            .flatten()
    }
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        frame: &mut DerivationFrame<'_, R, A>,
        k: &Self::Key,
    ) -> Computed<Self::Output> {
        let complete = match selected_units_known(frame) {
            Ok(complete) => complete,
            Err(cause) => return Computed::Unavailable(cause),
        };
        read("rust_unit_dependents", complete, |i, s| {
            rust_unit_dependents(i.connection(), s, k).map_err(record_route_store_error)
        })
    }
    fn output_projection(v: &Self::Output, h: &mut CanonicalHasher) {
        project_answer("rust_unit_dependents", v, h);
    }
}
macro_rules! path_kind {
 ($t:ident,$id:literal,$family:literal,$read:ident,$field:ident,$output:ty) => {
 pub struct $t;
 impl DerivationKind for $t {
  type Key=String; type Output=$output;
  const ID:DerivationKindId=DerivationKindId($id);
  const QUESTION_SHAPE: brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily = brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(Self::ID, true, false, path_kind!(@is_path $field), path_kind!(@is_name $field)); const STRATUM:u16=1; const VERIFY:Verification=Verification::Recompute; const CHILDREN:&'static [(DerivationKindId,u16)]=&[(RustSelectedUnitsKnown::ID,0),(RustFileAvailability::ID,0),(RustNameAvailability::ID,0)];
  fn question(k:&Self::Key)->DerivationQuestion { question(None, path_kind!(@path $field,k),path_kind!(@name $field,k)) }
  fn key_from_question(q:&DerivationQuestion)->Option<Self::Key> { if q.language==Some(Language::Rust)&&q.subject.is_none()&&path_kind!(@other_empty $field,q) { q.$field.as_deref().map(str::to_owned) } else { None } }
  #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
  fn compute<R:DerivationRevision,A:DerivationAuthority>(&self,frame:&mut DerivationFrame<'_,R,A>,k:&Self::Key)->Computed<Self::Output> { let complete=match selected_units_known(frame) { Ok(complete)=>complete, Err(cause)=>return Computed::Unavailable(cause) }; let complete = path_kind!(@local $field, frame, k, complete); read($family,complete,|i,s|$read(i.connection(),s,k).map_err(record_route_store_error)) }
  fn output_projection(v:&Self::Output,h:&mut CanonicalHasher) { project_answer($family,v,h); }
 }
 };
 (@local rel_path,$frame:ident,$k:ident,$complete:ident)=>{match $frame.demand::<RustFileAvailability>($k) { Demanded::Available { complete: local,.. }=>$complete && local, Demanded::Unavailable(cause)=>return Computed::Unavailable(cause) }};
 (@local name,$frame:ident,$k:ident,$complete:ident)=>{match $frame.demand::<RustNameAvailability>($k) { Demanded::Available {complete:local,..}=>$complete&&local,Demanded::Unavailable(cause)=>return Computed::Unavailable(cause) }};
 (@is_path rel_path)=>{true}; (@is_path name)=>{false};
 (@is_name name)=>{true}; (@is_name rel_path)=>{false};
 (@path rel_path,$k:ident)=>{Some($k.clone().into_boxed_str())}; (@path name,$k:ident)=>{None};
 (@name name,$k:ident)=>{Some($k.clone().into_boxed_str())}; (@name rel_path,$k:ident)=>{None};
 (@other_empty name,$q:ident)=>{$q.rel_path.is_none()}; (@other_empty rel_path,$q:ident)=>{$q.name.is_none()};
}
path_kind!(
    RustFileUnits,
    "derivation:rust_file_units:v1",
    "rust_file_units",
    rust_file_units,
    rel_path,
    Vec<SelectedRustUnit>
);
path_kind!(
    RustBroadFileUnits,
    "derivation:rust_broad_file_units:v1",
    "rust_broad_file_units",
    rust_broad_file_units,
    rel_path,
    Vec<SelectedRustUnit>
);
/// Lib and bin crate roots exposed under a crate name, including the names a
/// workspace dependency is renamed to. The name is normalized as the whole route
/// index normalizes it (`-` to `_`), so `dep-crate` and `dep_crate` ask the same
/// question and give the same answer. The stored crate and extern names are
/// already in normalized form.
pub struct RustCrateNameUnits;
impl DerivationKind for RustCrateNameUnits {
    type Key = String;
    type Output = Vec<(SelectedRustUnit, String, String)>;
    const ID: DerivationKindId = DerivationKindId("derivation:rust_crate_name_units:v2");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            false,
            false,
            true,
        );
    const STRATUM: u16 = 1;
    const VERIFY: Verification = Verification::Recompute;
    const CHILDREN: &'static [(DerivationKindId, u16)] = &[
        (RustSelectedUnitsKnown::ID, 0),
        (RustNameAvailability::ID, 0),
    ];
    fn question(k: &Self::Key) -> DerivationQuestion {
        question(None, None, Some(normalize_crate_name(k).into_boxed_str()))
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<Self::Key> {
        (q.language == Some(Language::Rust) && q.subject.is_none() && q.rel_path.is_none())
            .then(|| q.name.as_deref().map(normalize_crate_name))
            .flatten()
    }
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        frame: &mut DerivationFrame<'_, R, A>,
        name: &Self::Key,
    ) -> Computed<Self::Output> {
        let complete = match selected_units_known(frame) {
            Ok(complete) => complete,
            Err(cause) => return Computed::Unavailable(cause),
        };
        let normalized = normalize_crate_name(name);
        let complete = match frame.demand::<RustNameAvailability>(&normalized) {
            Demanded::Available {
                complete: local, ..
            } => complete && local,
            Demanded::Unavailable(cause) => return Computed::Unavailable(cause),
        };
        read("rust_crate_name_units", complete, |i, s| {
            rust_crate_name_units(i.connection(), s, &normalized).map_err(record_route_store_error)
        })
    }
    fn output_projection(v: &Self::Output, h: &mut CanonicalHasher) {
        project_answer("rust_crate_name_units", v, h);
    }
}
path_kind!(
    RustPackageUnits,
    "derivation:rust_package_units:v1",
    "rust_package_units",
    rust_package_units,
    name,
    Vec<(SelectedRustUnit, u32)>
);

#[derive(Debug, Clone)]
pub struct RustUnitRouteFragment {
    naming: Vec<(PathBuf, String, PathBuf)>,
    pub(crate) files: Vec<ProjectFile>,
    pub(crate) packages: Vec<(ProjectFile, Vec<String>)>,
    pub(crate) facts: HashMap<ProjectFile, RustModuleRouteFacts>,
    pub(crate) rows: Vec<RustCargoRouteSummaryRow>,
    /// Member files with no active placement in this unit, proven inactive or
    /// undecided (#11639).
    pub(crate) inactive: RustInactivePlacements,
    pub(crate) index: Arc<RustCargoRouteIndex>,
    /// Module candidates the build found missing from the selection and the
    /// listing certificate cannot prove absent: a `#[path]` target that is not
    /// a `.rs` name. The unit is incomplete while any exists.
    pub(crate) unproven_candidates: Vec<ProjectFile>,
}
impl RustUnitRouteFragment {
    /// Module candidates this unit's route build found missing and the listing
    /// certificate cannot prove absent.
    pub fn unproven_candidates(&self) -> &[ProjectFile] {
        &self.unproven_candidates
    }
    /// The external `mod` declarations of this unit's files, resolved against
    /// the selection.
    pub fn external_module_declarations(
        &self,
    ) -> &[brokk_bifrost_rust::cargo_routes::RustCargoModuleDeclaration] {
        self.index.external_module_declarations()
    }
}
fn path_bytes(path: &std::path::Path) -> Vec<u8> {
    brokk_bifrost_core::path_utils::workspace_relative_slash_path(path).into_bytes()
}
fn optional_bytes(hash: &mut CanonicalHasher, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            hash.value(&[1]);
            hash.value(value);
        }
        None => hash.value(&[0]),
    }
}
fn optional_path(hash: &mut CanonicalHasher, value: Option<&std::path::Path>) {
    optional_bytes(hash, value.as_ref().map(|p| path_bytes(p)).as_deref());
}
fn optional_file(hash: &mut CanonicalHasher, value: Option<&ProjectFile>) {
    optional_path(hash, value.map(ProjectFile::rel_path));
}
fn number(hash: &mut CanonicalHasher, value: usize) {
    hash.value(&(value as u64).to_be_bytes());
}
fn optional_number(hash: &mut CanonicalHasher, value: Option<usize>) {
    match value {
        Some(value) => {
            hash.value(&[1]);
            number(hash, value);
        }
        None => hash.value(&[0]),
    }
}
fn route_projection(row: &RustCargoRouteSummaryRow, h: &mut CanonicalHasher) {
    h.value(&row.unit_key);
    optional_path(h, row.manifest_directory.as_deref());
    h.value(row.target_kind.as_bytes());
    h.value(row.crate_name.as_bytes());
    h.value(row.edition.as_bytes());
    h.value(&[row.development_capable as u8]);
    optional_file(h, row.root_file.as_ref());
    optional_bytes(h, row.root_package.as_deref().map(str::as_bytes));
    optional_bytes(h, row.dependency_extern_name.as_deref().map(str::as_bytes));
    h.value(&[match row.dependency_kind {
        None => 0,
        Some(RustCargoDependencyKind::Normal) => 1,
        Some(RustCargoDependencyKind::Development) => 2,
        Some(RustCargoDependencyKind::Build) => 3,
    }]);
    optional_bytes(h, row.dependency_boundary.as_deref().map(str::as_bytes));
    optional_bytes(
        h,
        row.dependency_unit_key.as_ref().map(|key| key.as_slice()),
    );
    optional_bytes(h, row.dependency_target_kind.as_deref().map(str::as_bytes));
    optional_file(h, row.dependency_root_file.as_ref());
    optional_bytes(h, row.dependency_root_package.as_deref().map(str::as_bytes));
    optional_path(h, row.dependency_manifest_directory.as_deref());
}
fn facts_projection(facts: &RustModuleRouteFacts, h: &mut CanonicalHasher) {
    h.sequence("scopes", &facts.scopes, |h, s| {
        optional_number(h, s.parent);
        optional_number(h, s.declaration.map(|v| v.index()));
        h.value(s.module_name.as_bytes());
        optional_bytes(h, s.path_attribute.as_deref().map(str::as_bytes));
        h.value(encode_rust_visibility(&s.visibility).as_bytes());
        h.value(&[s.imports_macros as u8]);
        optional_number(h, s.resolution_scope.map(|v| v.index()));
        number(h, s.body_start);
        number(h, s.body_end);
    });
    h.sequence("routes", &facts.routes, |h, r| {
        number(h, r.scope);
        number(h, r.declaration.index());
        h.value(r.module_name.as_bytes());
        optional_bytes(h, r.path_attribute.as_deref().map(str::as_bytes));
        h.value(encode_rust_visibility(&r.visibility).as_bytes());
        h.value(&[r.imports_macros as u8, r.test_gated as u8]);
        h.value(encode_rust_cfg_condition(&r.cfg_condition).as_bytes());
        number(h, r.declaration_start);
        number(h, r.declaration_end);
        h.sequence("gates", &r.gates, |h, g| {
            h.value(g.macro_name.as_bytes());
            number(h, g.invocation_start);
        });
    });
    h.sequence("item-macros", &facts.item_macros, |h, m| {
        number(h, m.declaration.index());
        h.value(m.name.as_bytes());
        number(h, m.visible_after);
        number(h, m.scope_start);
        number(h, m.scope_end);
        h.value(&[
            m.passthrough as u8,
            m.arguments_only as u8,
            m.declares_no_item as u8,
            m.writes_only_impls as u8,
            m.exported as u8,
        ]);
        optional_bytes(
            h,
            m.decoration
                .as_ref()
                .map(encode_rust_cfg_condition)
                .as_deref()
                .map(str::as_bytes),
        );
    });
}
fn string_weight(value: &Option<String>) -> usize {
    value
        .as_ref()
        .map_or(0, |text| allocation_size(text.capacity()))
}
fn route_weight(row: &RustCargoRouteSummaryRow) -> usize {
    row.manifest_directory
        .as_ref()
        .map_or(0, |path| allocation_size(path.capacity()))
        + allocation_size(row.target_kind.capacity())
        + allocation_size(row.crate_name.capacity())
        + allocation_size(row.edition.capacity())
        + row
            .root_file
            .as_ref()
            .map_or(0, ProjectFile::allocated_heap_bytes)
        + string_weight(&row.root_package)
        + string_weight(&row.dependency_extern_name)
        + string_weight(&row.dependency_boundary)
        + string_weight(&row.dependency_target_kind)
        + row
            .dependency_root_file
            .as_ref()
            .map_or(0, ProjectFile::allocated_heap_bytes)
        + string_weight(&row.dependency_root_package)
        + row
            .dependency_manifest_directory
            .as_ref()
            .map_or(0, |path| allocation_size(path.capacity()))
}
fn strings_weight(parts: &Vec<String>) -> usize {
    allocated_vec_slot_bytes(parts)
        + parts
            .iter()
            .map(|part| allocation_size(part.capacity()))
            .sum::<usize>()
}
impl RetainedBytes for RustUnitRouteFragment {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + allocated_vec_slot_bytes(&self.naming)
            + self
                .naming
                .iter()
                .map(|(manifest, name, library)| {
                    allocation_size(manifest.capacity())
                        + allocation_size(name.capacity())
                        + allocation_size(library.capacity())
                })
                .sum::<usize>()
            + allocated_vec_slot_bytes(&self.files)
            + self
                .files
                .iter()
                .map(ProjectFile::allocated_heap_bytes)
                .sum::<usize>()
            + allocated_vec_slot_bytes(&self.packages)
            + self
                .packages
                .iter()
                .map(|(f, c)| f.allocated_heap_bytes() + strings_weight(c))
                .sum::<usize>()
            + allocated_table_slot_bytes::<(ProjectFile, RustModuleRouteFacts)>(
                self.facts.capacity(),
            )
            + self
                .facts
                .iter()
                .map(|(f, v)| f.allocated_heap_bytes() + v.allocated_retained_bytes())
                .sum::<usize>()
            + allocated_vec_slot_bytes(&self.rows)
            + self.rows.iter().map(route_weight).sum::<usize>()
            + [&self.inactive.proven_inactive, &self.inactive.undecided]
                .into_iter()
                .map(|files| {
                    allocated_table_slot_bytes::<ProjectFile>(files.capacity())
                        + files
                            .iter()
                            .map(ProjectFile::allocated_heap_bytes)
                            .sum::<usize>()
                })
                .sum::<usize>()
            + allocated_table_slot_bytes::<(ProjectFile, Vec<(String, RustPlacementState)>)>(
                self.inactive.placements.capacity(),
            )
            + self
                .inactive
                .placements
                .iter()
                .map(|(file, placements)| {
                    file.allocated_heap_bytes()
                        + allocated_vec_slot_bytes(placements)
                        + placements
                            .iter()
                            .map(|(path, _)| allocation_size(path.capacity()))
                            .sum::<usize>()
                })
                .sum::<usize>()
            + self.index.retained_bytes()
            + allocated_vec_slot_bytes(&self.unproven_candidates)
            + self
                .unproven_candidates
                .iter()
                .map(ProjectFile::allocated_heap_bytes)
                .sum::<usize>()
    }
}

/// The fragment is reusable when its per-unit rows and member facts are bound
/// to content identities. Module facts are deterministic for (Rust generation,
/// parse variant, blob OID) under a valid producer identity: sealed publication,
/// deterministic extraction, and an epoch-affecting Rust salt or
/// STRUCTURAL_FACTS_VERSION bump when extraction changes for unchanged bytes.
/// A family row-format pin alone is insufficient. See
/// `.agents/docs/cache-identity-levers.md`. If a producer later reads external
/// or configuration inputs, those inputs need identity coverage too.
pub struct RustUnitRoutes;
impl DerivationKind for RustUnitRoutes {
    type Key = SelectedRustUnit;
    type Output = RustUnitRouteFragment;
    const ID: DerivationKindId = DerivationKindId("derivation:rust_unit_routes:v1");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            true,
            false,
            false,
        );
    const STRATUM: u16 = 1;
    const VERIFY: Verification = Verification::BaseInputs;
    const CHILDREN: &'static [(DerivationKindId, u16)] =
        &[(RustUnitInputs::ID, 0), (RustUnitNaming::ID, 0)];
    fn question(k: &Self::Key) -> DerivationQuestion {
        question(Some(*k.key()), None, None)
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<Self::Key> {
        RustUnitInputs::key_from_question(q).map(SelectedRustUnit::replayed)
    }
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        frame: &mut DerivationFrame<'_, R, A>,
        unit: &Self::Key,
    ) -> Computed<Self::Output> {
        let unit = unit.key();
        let _scope = attribution::enter_scope("rust_unit_routes", CoverageClass::DeclaredInputs);
        let mut complete = match frame.demand::<RustUnitInputs>(unit) {
            Demanded::Available { complete, .. } => complete,
            Demanded::Unavailable(cause) => return Computed::Unavailable(cause),
        };
        let read = derivation_host::with_bound_inventory(|inventory| {
            let snapshot = derivation_host::selected_rust_snapshot(inventory)?;
            let connection = inventory.connection();
            let routes =
                AnalyzerStore::rust_summary_cargo_route_rows_for_unit(connection, &snapshot, unit)
                    .map_err(record_route_store_error)?;
            Ok::<_, String>((snapshot, routes))
        });
        let (snapshot, routes) = match read {
            Ok(value) => value,
            Err(error) => return Computed::Unavailable(UnavailableCause::Failed(error.into())),
        };
        // Why this unit's routes may omit something, named in the gap so a
        // partial answer says which evidence it lacks.
        let mut causes = Vec::new();
        if !complete {
            causes.push("the unit's own inventory is incomplete".to_owned());
        }
        if routes.is_empty() {
            complete = false;
            causes.push("the unit has no Cargo route rows".to_owned());
        }
        let mut dependency_keys = routes
            .iter()
            .filter_map(|r| r.dependency_unit_key)
            .collect::<Vec<_>>();
        dependency_keys.sort_unstable();
        dependency_keys.dedup();
        for key in dependency_keys {
            match frame.demand::<RustUnitInputs>(&key) {
                Demanded::Available {
                    complete: input_complete,
                    ..
                } => {
                    if !input_complete {
                        complete = false;
                        causes.push(format!("dependency unit {key:02x?} is incomplete"));
                    }
                }
                Demanded::Unavailable(cause) => return Computed::Unavailable(cause),
            }
        }
        let rootless: Vec<_> = routes
            .iter()
            .filter(|r| {
                r.dependency_boundary.as_deref() == Some("workspace")
                    && r.dependency_root_rel_path.is_none()
            })
            .map(|r| r.dependency_extern_name.clone())
            .collect();
        if !rootless.is_empty() {
            complete = false;
            causes.push(format!("workspace dependencies have no root: {rootless:?}"));
        }
        let root = derivation_host::with_current_analyzer(|analyzer| {
            analyzer.project().root().to_path_buf()
        });
        let (package, members, not_active) = match unit_members(unit) {
            Ok(v) => v,
            Err(e) => return Computed::Unavailable(UnavailableCause::Failed(e.into())),
        };
        let oids = members
            .iter()
            .filter_map(|(_, oid)| *oid)
            .collect::<Vec<_>>();
        let progress = route_build_progress();
        let stored = derivation_host::with_bound_inventory(|inventory| {
            AnalyzerStore::rust_module_route_facts_on_connection(
                inventory.connection(),
                &BlobKey::unvaried(Oid::zero(), "rust"),
                snapshot.generation,
                &oids,
                &progress,
            )
            .map_err(record_route_store_error)
        });
        let stored = match stored {
            Ok(Some(stored)) => stored,
            Ok(None) => return Computed::Unavailable(UnavailableCause::Cancelled),
            Err(error) => return Computed::Unavailable(UnavailableCause::Failed(error.into())),
        };
        let mut facts = HashMap::default();
        let mut unpublished = Vec::new();
        for (file, oid) in &members {
            let Some(fact) = oid.as_ref().and_then(|oid| stored.get(oid)) else {
                complete = false;
                unpublished.push(file.rel_path().to_path_buf());
                continue;
            };
            facts.insert(file.clone(), fact.clone());
        }
        if !unpublished.is_empty() {
            causes.push(format!(
                "members have no published route facts: {unpublished:?}"
            ));
        }
        let rows = summary_route_rows(&root, routes);
        let packages = package
            .iter()
            .map(|row| {
                (
                    ProjectFile::new(root.clone(), row.rel_path.clone()),
                    row.package_components.clone(),
                )
            })
            .collect();
        let files: Vec<_> = members.into_iter().map(|(file, _)| file).collect();
        let naming = match frame.demand::<RustUnitNaming>(unit) {
            Demanded::Available {
                value,
                complete: naming_complete,
                ..
            } => {
                if !naming_complete {
                    complete = false;
                    causes.push("the unit's crate naming is incomplete".to_owned());
                }
                value
            }
            Demanded::Unavailable(cause) => return Computed::Unavailable(cause),
        };
        let (index, unproven_candidates) =
            match selected_route_index(&files, &facts, &rows, &naming, &not_active) {
                Ok(built) => built,
                Err(cause) => return Computed::Unavailable(cause),
            };
        if !unproven_candidates.is_empty() {
            complete = false;
            causes.push("module files the listing cannot prove absent".to_owned());
            derivation_host::with_current_analyzer(|a| {
                a.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                    brokk_bifrost_core::bounded_output::bounded_diagnostic_items(format_args!("Rust unit {unit:02x?} names module files the listing certificate cannot prove absent: {unproven_candidates:?}"), format_args!("Rust unit {unit:02x?} names module files the listing certificate cannot prove absent; detail_kind=ModuleFile"), unproven_candidates.iter())
                    .into(),
                ))
            });
        }
        if !complete {
            derivation_host::with_current_analyzer(|a| {
                a.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                    brokk_bifrost_core::bounded_output::bounded_diagnostic_items(format_args!("Rust unit {unit:02x?} has incomplete published route evidence: {causes:?}"), format_args!("Rust unit {unit:02x?} has incomplete published route evidence; detail_kind=RouteCause"), causes.iter())
                    .into(),
                ))
            });
        }
        let validity = ReuseValidity::Reusable;
        Computed::Available {
            value: RustUnitRouteFragment {
                naming: naming.to_vec(),
                files,
                packages,
                facts,
                rows,
                inactive: not_active,
                index: Arc::new(index),
                unproven_candidates,
            },
            complete,
            validity,
            reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
        }
    }
    fn output_projection(v: &Self::Output, hash: &mut CanonicalHasher) {
        RustUnitNaming::output_projection(&v.naming, hash);
        let mut rows = v
            .rows
            .iter()
            .map(|row| {
                let mut h = CanonicalHasher::new(b"rust-route-row:v1");
                route_projection(row, &mut h);
                h.finish()
            })
            .collect::<Vec<_>>();
        rows.sort_unstable();
        hash.sequence("route-rows", &rows, |h, row| h.value(row));
        let mut files = v
            .files
            .iter()
            .map(|file| path_bytes(file.rel_path()))
            .collect::<Vec<_>>();
        files.sort_unstable();
        hash.sequence("member-files", &files, |h, file| h.value(file));
        let mut packages = v
            .packages
            .iter()
            .map(|(file, components)| {
                let mut h = CanonicalHasher::new(b"rust-route-package:v1");
                h.value(&path_bytes(file.rel_path()));
                h.sequence("components", components, |h, c| h.value(c.as_bytes()));
                h.finish()
            })
            .collect::<Vec<_>>();
        packages.sort_unstable();
        hash.sequence("member-packages", &packages, |h, row| h.value(row));
        let mut facts = v
            .facts
            .iter()
            .map(|(file, facts)| {
                let mut h = CanonicalHasher::new(b"rust-route-facts:v1");
                h.value(&path_bytes(file.rel_path()));
                facts_projection(facts, &mut h);
                h.finish()
            })
            .collect::<Vec<_>>();
        facts.sort_unstable();
        hash.sequence("module-facts", &facts, |h, row| h.value(row));
        for (label, files) in [
            ("inactive-files", &v.inactive.proven_inactive),
            ("undecided-files", &v.inactive.undecided),
        ] {
            if !files.is_empty() {
                let mut paths = files
                    .iter()
                    .map(|file| path_bytes(file.rel_path()))
                    .collect::<Vec<_>>();
                paths.sort_unstable();
                hash.sequence(label, &paths, |h, file| h.value(file));
            }
        }
        if !v.inactive.placements.is_empty() {
            let mut placements = v
                .inactive
                .placements
                .iter()
                .flat_map(|(file, placements)| {
                    placements.iter().map(move |(module_path, state)| {
                        (
                            path_bytes(file.rel_path()),
                            module_path.clone(),
                            *state as u8,
                        )
                    })
                })
                .collect::<Vec<_>>();
            placements.sort_unstable();
            hash.sequence("placement-activity", &placements, |h, row| {
                h.value(&row.0);
                h.value(row.1.as_bytes());
                h.value(&[row.2]);
            });
        }
    }
}

/// The files that can reference one target root, as the whole route index
/// lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustRootReachability {
    pub root: String,
    pub files: Vec<String>,
}

/// The reachability of every root that a unit's route rows list, synthetic
/// `include!` roots included, sorted by root. A unit's entry for a root is that
/// root's reachability through this unit and its dependents.
///
/// The whole index's `files_that_can_reference_target_of(root)` is the union of
/// the entries for that root from every unit that lists the root. Two Cargo
/// targets can share a root file (a library and a binary both configured with
/// `path = "src/shared.rs"`), and a crate that depends on only one of them is
/// in only that unit's entry, so a single unit's entry may be a strict subset
/// of the whole index's answer.
///
/// A consumer takes its target file's roots from
/// `RustFileRoutes::target_roots(file)` and unions the entries for those roots
/// from the reachability of the units that hold them. The answer carries no
/// placement classification: the whole index roots a file declared by an
/// `include!`d file at that file, not at the crate root, and a classification
/// for a unit's roots taken together disagrees with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustReachableFiles {
    pub roots: Vec<RustRootReachability>,
}

impl RetainedBytes for RustReachableFiles {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + allocated_vec_slot_bytes(&self.roots)
            + self
                .roots
                .iter()
                .map(|entry| allocation_size(entry.root.capacity()) + strings_weight(&entry.files))
                .sum::<usize>()
    }
}

pub struct RustTargetReachability;
impl DerivationKind for RustTargetReachability {
    type Key = SelectedRustUnit;
    type Output = RustReachableFiles;
    const ID: DerivationKindId = DerivationKindId("derivation:rust_target_reachability:v2");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            true,
            false,
            false,
        );
    const STRATUM: u16 = 2;
    const VERIFY: Verification = Verification::BaseInputs;
    const CHILDREN: &'static [(DerivationKindId, u16)] = &[
        (RustUnitRoutes::ID, 1),
        (RustUnitDependents::ID, 1),
        (RustUnitNaming::ID, 0),
    ];
    fn question(k: &Self::Key) -> DerivationQuestion {
        question(Some(*k.key()), None, None)
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<Self::Key> {
        RustUnitInputs::key_from_question(q).map(SelectedRustUnit::replayed)
    }
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        frame: &mut DerivationFrame<'_, R, A>,
        unit: &Self::Key,
    ) -> Computed<Self::Output> {
        let _scope =
            attribution::enter_scope("rust_target_reachability", CoverageClass::DeclaredInputs);
        let mut complete = true;
        let dependents = match frame.demand::<RustUnitDependents>(unit.key()) {
            Demanded::Available {
                value,
                complete: input_complete,
                ..
            } => {
                complete &= input_complete;
                value
                    .iter()
                    .map(|(dependent, _)| dependent.clone())
                    .collect::<HashSet<_>>()
            }
            Demanded::Unavailable(cause) => return Computed::Unavailable(cause),
        };
        let target = match frame.demand::<RustUnitRoutes>(unit) {
            Demanded::Available {
                value,
                complete: input_complete,
                ..
            } => {
                complete &= input_complete;
                value
            }
            Demanded::Unavailable(cause) => return Computed::Unavailable(cause),
        };
        let mut files = target.files.clone();
        let mut facts = target.facts.clone();
        let mut rows = target.rows.clone();
        let mut inactive = target.inactive.clone();
        let target_roots = target
            .rows
            .iter()
            .filter_map(|row| row.root_file.clone())
            .collect::<HashSet<_>>();
        let mut naming = Vec::new();
        for key in std::iter::once(unit.key()).chain(dependents.iter().map(SelectedRustUnit::key)) {
            match frame.demand::<RustUnitNaming>(key) {
                Demanded::Available {
                    value,
                    complete: input_complete,
                    ..
                } => {
                    complete &= input_complete;
                    naming.extend(value.iter().cloned())
                }
                Demanded::Unavailable(cause) => return Computed::Unavailable(cause),
            }
        }
        naming.sort_unstable();
        naming.dedup();
        for dependent in dependents {
            let fragment = match frame.demand::<RustUnitRoutes>(&dependent) {
                Demanded::Available {
                    value,
                    complete: input_complete,
                    ..
                } => {
                    complete &= input_complete;
                    value
                }
                Demanded::Unavailable(cause) => return Computed::Unavailable(cause),
            };
            files.extend(fragment.files.iter().cloned());
            facts.extend(
                fragment
                    .facts
                    .iter()
                    .map(|(file, fact)| (file.clone(), fact.clone())),
            );
            rows.extend(fragment.rows.iter().cloned());
            inactive.extend(&fragment.inactive);
        }
        files.sort_unstable();
        files.dedup();
        // Every unproven candidate of this merged build is a candidate of one
        // of the fragments demanded above, and each of those already made
        // `complete` false.
        let (index, _) = match selected_route_index(&files, &facts, &rows, &naming, &inactive) {
            Ok(built) => built,
            Err(cause) => return Computed::Unavailable(cause),
        };
        let slash = |file: &ProjectFile| {
            brokk_bifrost_core::path_utils::workspace_relative_slash_path(file.rel_path())
        };
        let mut answer = target_roots
            .iter()
            .map(|root| {
                let mut files = index
                    .files_that_can_reference_target_of(root)
                    .iter()
                    .map(slash)
                    .collect::<Vec<_>>();
                files.sort_unstable();
                files.dedup();
                RustRootReachability {
                    root: slash(root),
                    files,
                }
            })
            .collect::<Vec<_>>();
        answer.sort_unstable_by(|left, right| left.root.cmp(&right.root));
        Computed::Available {
            value: RustReachableFiles { roots: answer },
            complete,
            validity: ReuseValidity::Reusable,
            reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
        }
    }
    fn output_projection(v: &Self::Output, hash: &mut CanonicalHasher) {
        hash.sequence("root-reachability", &v.roots, |h, entry| {
            h.value(entry.root.as_bytes());
            h.sequence("files", &entry.files, |h, file| h.value(file.as_bytes()));
        });
    }
}

/// One member file of a unit with the naming the whole package index keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustUnitPackageRow {
    pub rel_path: String,
    pub package_components: Vec<String>,
    pub crate_name: String,
    pub target_kind: String,
    pub is_root_member: bool,
}

impl RetainedBytes for RustUnitPackageRow {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + allocation_size(self.rel_path.capacity())
            + strings_weight(&self.package_components)
            + allocation_size(self.crate_name.capacity())
            + allocation_size(self.target_kind.capacity())
    }
}

/// The package rows of one unit, from its summary rows alone: no module facts
/// and no route index. A package question therefore stays answerable when
/// module facts are missing, as does the partial route index. `complete` is only this unit's member
/// listing; whether the workspace's units are all known is the other kinds'
/// question (`RustSelectedUnitsKnown`).
pub struct RustUnitPackageRows;
impl DerivationKind for RustUnitPackageRows {
    type Key = SelectedRustUnit;
    type Output = Vec<RustUnitPackageRow>;
    const ID: DerivationKindId = DerivationKindId("derivation:rust_unit_package_rows:v1");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            true,
            false,
            false,
        );
    const STRATUM: u16 = 0;
    const VERIFY: Verification = Verification::Recompute;
    const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
    fn question(k: &Self::Key) -> DerivationQuestion {
        question(Some(*k.key()), None, None)
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<Self::Key> {
        RustUnitInputs::key_from_question(q).map(SelectedRustUnit::replayed)
    }
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        _: &mut DerivationFrame<'_, R, A>,
        unit: &Self::Key,
    ) -> Computed<Self::Output> {
        let unit = unit.key();
        let _scope =
            attribution::enter_scope("rust_unit_package_rows", CoverageClass::RecomputeOnCurrency);
        match unit_intentionally_unavailable(unit) {
            Ok(true) => {
                return Computed::Available {
                    value: Vec::new(),
                    complete: false,
                    validity: ReuseValidity::Reusable,
                    reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
                };
            }
            Ok(false) => {}
            Err(error) => return Computed::Unavailable(UnavailableCause::Failed(error.into())),
        }
        let read = derivation_host::with_bound_inventory(|inventory| {
            let snapshot = derivation_host::selected_rust_snapshot(inventory)?;
            rust_unit_package_rows(inventory.connection(), &snapshot, unit)
                .map_err(record_route_store_error)
        });
        let (rows, mut complete) = match read {
            Ok(Some((rows, complete))) => {
                let complete = complete && !rows.is_empty();
                (rows, complete)
            }
            Ok(None) => (Vec::new(), false),
            Err(error) => return Computed::Unavailable(UnavailableCause::Failed(error.into())),
        };
        if !complete {
            derivation_host::with_current_analyzer(|a| {
                a.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                    format!("Rust unit {unit:02x?} has incomplete inventory").into(),
                ))
            });
        }
        // A member whose every declaring edge the selection removed, retargeted
        // or gated off is no longer proven to belong to the unit, and the
        // selection may place it elsewhere in a way the persisted unit cannot
        // see: leave it out and say the listing is partial.
        let (rows, unplaced): (Vec<_>, Vec<_>) =
            rows.into_iter().partition(|row| !row.unplaced_by_selection);
        if !unplaced.is_empty() {
            complete = false;
            let unplaced = unplaced
                .iter()
                .map(|row| row.rel_path.as_str())
                .collect::<Vec<_>>();
            derivation_host::with_current_analyzer(|a| {
                a.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                    brokk_bifrost_core::bounded_output::bounded_diagnostic_items(format_args!("Rust unit {unit:02x?} members unplaced by the selection: {unplaced:?}"), format_args!("Rust unit {unit:02x?} members unplaced by the selection; detail_kind=Member"), unplaced.iter())
                    .into(),
                ))
            });
        }
        let mut rows = rows
            .into_iter()
            .map(|row| RustUnitPackageRow {
                rel_path: row.rel_path,
                package_components: row.package_components,
                crate_name: row.crate_name,
                target_kind: row.target_kind,
                is_root_member: row.is_root_member,
            })
            .collect::<Vec<_>>();
        rows.sort_unstable_by(|left, right| left.rel_path.cmp(&right.rel_path));
        Computed::Available {
            value: rows,
            complete,
            validity: ReuseValidity::Reusable,
            reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
        }
    }
    fn output_projection(v: &Self::Output, hash: &mut CanonicalHasher) {
        hash.sequence("package-rows", v, |h, row| {
            h.value(row.rel_path.as_bytes());
            h.sequence("components", &row.package_components, |h, c| {
                h.value(c.as_bytes())
            });
            h.value(row.crate_name.as_bytes());
            h.value(row.target_kind.as_bytes());
            h.value(&[row.is_root_member as u8]);
        });
    }
}

pub fn register(d: &AnalyzerDerivations) {
    d.register(RustSelectedUnitsKnown);
    d.register(RustFileAvailability);
    d.register(RustNameAvailability);
    d.register(RustUnitInputs);
    d.register(RustUnitConfiguration);
    d.register(RustUnitNaming);
    d.register(RustUnitDependencyIdentities);
    d.register(RustUnitDependents);
    d.register(RustFileUnits);
    d.register(RustBroadFileUnits);
    d.register(RustCrateNameUnits);
    d.register(RustPackageUnits);
    d.register(RustUnitRoutes);
    d.register(RustTargetReachability);
    d.register(RustUnitPackageRows);
    d.register(RustLocalGlobNameAbsence);
}

// Shared by whole-index and per-unit route composition.
pub(super) fn summary_route_rows(
    root: &std::path::Path,
    stored_route_rows: Vec<
        brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::RustSummaryCargoRouteRow,
    >,
) -> Vec<RustCargoRouteSummaryRow> {
    stored_route_rows
        .into_iter()
        .map(|row| {
            let root_file = row
                .root_rel_path
                .map(|path| ProjectFile::new(root.to_path_buf(), path));
            let dependency_root_file = row
                .dependency_root_rel_path
                .map(|path| ProjectFile::new(root.to_path_buf(), path));
            let manifest_directory = row.manifest_rel_path.map(|path| {
                PathBuf::from(path)
                    .parent()
                    .unwrap_or(std::path::Path::new(""))
                    .to_path_buf()
            });
            let dependency_manifest_directory = row.dependency_manifest_rel_path.map(|path| {
                PathBuf::from(path)
                    .parent()
                    .unwrap_or(std::path::Path::new(""))
                    .to_path_buf()
            });
            let root_package = row
                .root_package_components
                .map(|components| components.join("."));
            let dependency_root_package = row
                .dependency_root_package_components
                .map(|components| components.join("."));
            let dependency_kind = row.dependency_kind.map(|kind| match kind.as_str() {
                "normal" => RustCargoDependencyKind::Normal,
                "dev" => RustCargoDependencyKind::Development,
                "build" => RustCargoDependencyKind::Build,
                _ => panic!("unknown Rust dependency kind {kind:?}"),
            });
            RustCargoRouteSummaryRow {
                unit_key: row.unit_key,
                manifest_directory,
                target_kind: row.target_kind,
                crate_name: row.crate_name,
                edition: row.edition,
                development_capable: row.development_capable,
                root_file,
                root_package,
                dependency_extern_name: row.dependency_extern_name,
                dependency_kind,
                dependency_boundary: row.dependency_boundary,
                dependency_unit_key: row.dependency_unit_key,
                dependency_target_kind: row.dependency_target_kind,
                dependency_root_file,
                dependency_root_package,
                dependency_manifest_directory,
            }
        })
        .collect::<Vec<_>>()
}

/// The encoded name holds parser-projected import coordinates and the queried
/// namespace/name. It is a question codec, not source syntax to reparse.
pub struct RustLocalGlobNameAbsence;
impl DerivationKind for RustLocalGlobNameAbsence {
    type Key = (String, String);
    type Output = brokk_bifrost_rust::graph_support::RustGlobNameAbsence;
    const ID: DerivationKindId = DerivationKindId("derivation:rust_local_glob_name_absence:v1");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            false,
            true,
            true,
        );
    const STRATUM: u16 = 2;
    // File membership and every local closure unit are recorded below. Their
    // identities cover import facts, export alternatives, gaps and selected
    // member content, so an unchanged input set can reuse this exact answer
    // across the Main bridge's successive reader leases.
    const VERIFY: Verification = Verification::BaseInputs;
    const CHILDREN: &'static [(DerivationKindId, u16)] =
        &[(RustFileUnits::ID, 1), (RustUnitInputs::ID, 0)];
    fn question(key: &Self::Key) -> DerivationQuestion {
        DerivationQuestion {
            language: Some(Language::Rust),
            subject: None,
            rel_path: Some(key.0.clone().into()),
            name: Some(key.1.clone().into()),
        }
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<Self::Key> {
        if q.language != Some(Language::Rust) || q.subject.is_some() {
            return None;
        }
        Some((q.rel_path.as_deref()?.into(), q.name.as_deref()?.into()))
    }
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        frame: &mut DerivationFrame<'_, R, A>,
        key: &Self::Key,
    ) -> Computed<Self::Output> {
        let _scope = attribution::enter_scope(
            "rust_local_glob_name_absence",
            CoverageClass::DeclaredInputs,
        );
        let result = (|| -> Result<_, String> {
            let (start, segments, namespace, name): (usize, Vec<String>, String, String) =
                serde_json::from_str(&key.1).map_err(|error| error.to_string())?;
            let namespace = match namespace.as_str() {
                "type" => brokk_bifrost_rust::graph_support::RustGlobNamespace::Type,
                "macro" => brokk_bifrost_rust::graph_support::RustGlobNamespace::Macro,
                _ => return Err(format!("invalid local glob namespace: {namespace:?}")),
            };
            derivation_host::with_bound_inventory(|inventory| {
                // The bridge admits only a selection whose changes cannot reach
                // this glob's closure; a bound inventory that still overlays a
                // file the closure lists answers from rows that file made stale.
                let overlaid = brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_selection_overlay_paths(inventory.connection()).map_err(record_route_store_error)?;
                if !overlaid.is_empty()
                    && brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_local_glob_closure_reads_paths(inventory.connection(), &key.0, &overlaid).map_err(record_route_store_error)?
                {
                    return Ok(brokk_bifrost_rust::graph_support::RustGlobNameAbsence::Incomplete);
                }
                AnalyzerStore::rust_local_glob_name_absence(
                    inventory.connection(),
                    &key.0,
                    start,
                    &segments,
                    namespace,
                    &name,
                )
                .map_err(record_route_store_error)
            })
        })();
        let answer = match result {
            Ok(answer) => answer,
            Err(error) => return Computed::Unavailable(UnavailableCause::Failed(error.into())),
        };
        if answer != brokk_bifrost_rust::graph_support::RustGlobNameAbsence::ClosedAbsent {
            // Refusal and positive competition are operational outcomes. Do
            // not retain them as reusable proofs or erase their typed cause
            // behind a crate-wide inventory incompleteness diagnostic.
            return Computed::Available {
                value: answer,
                complete: true,
                validity: ReuseValidity::NotReusable(
                    brokk_bifrost_semantic::analyzer::semantic::derivation::NotReusableCause::InvalidDependencyEvidence),
                reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
            };
        }
        let units = match frame.demand::<RustFileUnits>(&key.0) {
            Demanded::Available {
                value,
                complete: true,
                ..
            } => value,
            Demanded::Available { .. } => {
                return Computed::Unavailable(UnavailableCause::Incomplete(
                    IncompleteReason::Answer,
                ));
            }
            Demanded::Unavailable(cause) => return Computed::Unavailable(cause),
        };
        // Record the summaries that the local selected dependency closure can
        // read, including empty-name answers. The recursive relation is SQL's
        // deduplicated fixed point and never becomes a retained workspace map.
        for unit in units.iter() {
            let dependencies = derivation_host::with_bound_inventory(|inventory| {
                let mut statement = inventory.connection().prepare_cached(
                    "SELECT unit_key FROM temp.selected_rust_unit_closure WHERE root_unit_key=?1 ORDER BY unit_key")?;
                statement
                    .query_map([unit.key().as_slice()], |row| row.get::<_, Vec<u8>>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()
            });
            let dependencies = match dependencies {
                Ok(value) => value,
                Err(error) => {
                    record_route_store_error(error);
                    return Computed::Unavailable(UnavailableCause::StoreFailure);
                }
            };
            for dependency in dependencies {
                let dependency: [u8; 32] =
                    dependency.try_into().expect("selected unit digest width");
                match frame.demand::<RustUnitInputs>(&dependency) {
                    Demanded::Available { complete: true, .. } => (),
                    Demanded::Available { .. } => {
                        return Computed::Unavailable(UnavailableCause::Incomplete(
                            IncompleteReason::Answer,
                        ));
                    }
                    Demanded::Unavailable(cause) => return Computed::Unavailable(cause),
                }
            }
        }
        Computed::Available {
            value: answer,
            complete: true,
            validity: ReuseValidity::Reusable,
            reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
        }
    }
    fn output_projection(value: &Self::Output, hash: &mut CanonicalHasher) {
        hash.value(&[*value as u8]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::MultiAnalyzer;
    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
    use brokk_bifrost_analysis::analyzer::store_support::selection_test_support::SelectionFixture;
    use brokk_bifrost_core::retention_budget::RetentionBudget;
    use brokk_bifrost_semantic::analyzer::semantic::derivation::Demanded;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#13337: route input receipts omitted gap-derived file and placement activity")]
    fn activity_changes_invalidate_route_inputs_while_inventory_stays_open() {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"activity\"\nversion = \"0.1.0\"\n",
            )
            .file("src/lib.rs", "pub struct Item;\n")
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let analyzer = brokk_bifrost_analysis::analyzer::resolve_analyzer::<
            super::super::RustAnalyzer,
        >(workspace.analyzer())
        .unwrap();
        let store = workspace.store().unwrap();
        // Keep the same summary, broad bit and source bytes. Only the decoded
        // activity answer changes, so a Boolean-only receipt cannot detect it.
        let summary = store.execute_selection_publication(move |conn| {
            let _fixture = brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
            let summary: i64 = conn.query_row(
                "SELECT summary_id FROM rust_resolution_unit_summary_contexts WHERE crate_name='activity'",
                [], |row| row.get(0),
            ).unwrap();
            conn.execute(
                "UPDATE rust_resolution_unit_summary_contexts SET broad_complete=0 WHERE summary_id=?1",
                [summary],
            ).unwrap();
            conn.execute(
                "INSERT INTO rust_resolution_unit_summary_gaps(summary_id,gap_kind,subject,detail) VALUES(?1,'unknown_activation','crate::ghost',jsonb(?2))",
                rusqlite::params![summary, r#"{"path":"src/ghost_a.rs"}"#],
            ).unwrap();
            summary
        });
        let host = AnalyzerDerivations::new(&RetentionBudget::for_test_capacity(10_000_000));
        let read_answer = |host: &AnalyzerDerivations| {
            let read = analyzer
                .open_selected_rust_inventory(
                    &brokk_bifrost_core::cancellation::CancellationToken::default(),
                )
                .unwrap();
            let brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome::Ready(read) = read else { panic!("selected inventory unavailable") };
            let unit = match host.demand::<RustFileUnits>(analyzer, &read, &"src/lib.rs".to_owned())
            {
                Demanded::Available { value, .. } => value[0].clone(),
                Demanded::Unavailable(cause) => panic!("membership: {cause:?}"),
            };
            let input = match host.demand::<RustUnitInputs>(analyzer, &read, unit.key()) {
                Demanded::Available {
                    value, complete, ..
                } => {
                    assert!(!complete, "the broad inventory stays open");
                    *value
                }
                Demanded::Unavailable(cause) => panic!("inputs: {cause:?}"),
            };
            let routes = match host.demand::<RustUnitRoutes>(analyzer, &read, &unit) {
                Demanded::Available {
                    identity, complete, ..
                } => {
                    assert!(!complete);
                    identity
                }
                Demanded::Unavailable(cause) => panic!("routes: {cause:?}"),
            };
            (input, routes)
        };
        let initial = read_answer(&host);
        store.execute_selection_publication(move |conn| {
            let _fixture = brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
            conn.execute(
                "UPDATE rust_resolution_unit_summary_gaps SET detail=jsonb(?2) WHERE summary_id=?1 AND gap_kind='unknown_activation' AND subject='crate::ghost'",
                rusqlite::params![summary, r#"{"path":"src/ghost_b.rs"}"#],
            ).unwrap();
        });
        let file_changed = read_answer(&host);
        let scratch = AnalyzerDerivations::new(&RetentionBudget::for_test_capacity(10_000_000));
        assert_eq!(
            file_changed,
            read_answer(&scratch),
            "warm routes must equal fresh routes after a gap path edit"
        );
        assert_ne!(initial.0, file_changed.0, "file activity must be recorded");
        assert_ne!(
            initial.1, file_changed.1,
            "BaseInputs must recompute routes"
        );
        store.execute_selection_publication(move |conn| {
            let _fixture = brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
            conn.execute(
                "UPDATE rust_resolution_unit_summary_gaps SET subject='crate' WHERE summary_id=?1 AND gap_kind='unknown_activation' AND subject='crate::ghost'",
                [summary],
            ).unwrap();
        });
        let placement_changed = read_answer(&host);
        assert_ne!(
            file_changed.0, placement_changed.0,
            "placement activity must be recorded"
        );
        assert_ne!(
            file_changed.1, placement_changed.1,
            "routes must see the new placement activity"
        );
        let scratch = AnalyzerDerivations::new(&RetentionBudget::for_test_capacity(10_000_000));
        assert_eq!(
            placement_changed,
            read_answer(&scratch),
            "warm routes must equal fresh routes after a placement edit"
        );
    }

    #[test]
    #[hardwon("#9737: an empty selected Rust unit set was complete without a listing certificate")]
    fn empty_unit_set_is_complete_only_under_a_certified_listing() {
        let mut fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let analyzer = MultiAnalyzer::default();
        let missing = "src/missing.rs".to_string();
        let complete = |fixture: &SelectionFixture| {
            let read = fixture.open_ready(&[]);
            let host = AnalyzerDerivations::new(&RetentionBudget::for_test_capacity(1_000_000));
            match host.demand::<RustFileUnits>(&analyzer, &read, &missing) {
                Demanded::Available { complete, .. } => complete,
                Demanded::Unavailable(cause) => panic!("unavailable: {cause:?}"),
            }
        };
        assert!(!complete(&fixture), "no certificate is not a proof");
        // The revision readers can select has no certificate, and a revision's
        // certificate is written once, so every certificate opens a revision and
        // the question is read there.
        let uncertified = fixture.snapshots["rust"].clone();
        let failed = fixture
            .store
            .publish_rust_source_listing(
                &uncertified,
                brokk_bifrost_analysis::analyzer::store::RustListingInput::new(
                    brokk_bifrost_analysis::analyzer::store::rust_source_listing_derivation_identity(),
                    vec![("x.rs".to_string(), "unreadable".to_string())],
                ),
                Default::default(),
            )
            .unwrap();
        assert_eq!(failed.revision, uncertified.revision + 1);
        assert!(
            !complete(&fixture),
            "the revision without a certificate still reads none"
        );
        fixture.snapshots.insert("rust".into(), failed.clone());
        assert!(!complete(&fixture), "a failed certificate is not a proof");
        let certified = fixture
            .store
            .publish_rust_source_listing(
                &failed,
                brokk_bifrost_analysis::analyzer::store::RustListingInput::new(
                    brokk_bifrost_analysis::analyzer::store::rust_source_listing_derivation_identity(),
                    Vec::new(),
                ),
                Default::default(),
            )
            .unwrap();
        assert_eq!(certified.revision, failed.revision + 1);
        assert!(
            !complete(&fixture),
            "the failed revision still reads its own certificate"
        );
        fixture.snapshots.insert("rust".into(), certified);
        assert!(complete(&fixture));
    }

    #[test]
    #[hardwon("#9737: the route fragment charged a file by path length and two words")]
    fn fragment_budget_covers_every_file_allocation() {
        let root = if cfg!(windows) {
            r"C:\workspace"
        } else {
            "/workspace"
        };
        let file = ProjectFile::new(root, "src/a/very/deeply/nested/module/path/lib.rs");
        let fragment = RustUnitRouteFragment {
            naming: Vec::new(),
            files: vec![file.clone()],
            packages: vec![(file.clone(), Vec::new())],
            facts: HashMap::default(),
            rows: Vec::new(),
            inactive: RustInactivePlacements::default(),
            index: Arc::new(RustCargoRouteIndex::default()),
            unproven_candidates: Vec::new(),
        };
        // The file appears twice, once in `files` and once in `packages`. Each
        // charge covers the handle and everything it owns, as
        // `ProjectFile::retained_bytes` counts it.
        assert!(
            fragment.retained_bytes()
                >= std::mem::size_of::<RustUnitRouteFragment>()
                    + 2 * file.retained_bytes()
                    + fragment.index.retained_bytes()
        );
    }

    #[test]
    fn empty_selected_rust_route_questions_are_available() {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"routes\"\nversion = \"0.1.0\"\n",
            )
            .file("src/lib.rs", "")
            .build();
        let workspace = project.certified_workspace_analyzer(
            brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
        );
        let analyzer = brokk_bifrost_analysis::analyzer::resolve_analyzer::<
            super::super::RustAnalyzer,
        >(workspace.analyzer())
        .unwrap();
        let read = analyzer
            .open_selected_rust_inventory(
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .unwrap();
        let brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome::Ready(read) = read else { panic!("selected inventory unavailable") };
        let host = AnalyzerDerivations::new(&RetentionBudget::for_test_capacity(1_000_000));
        assert!(matches!(
            host.demand::<RustUnitInputs>(analyzer, &read, &[0; 32]),
            Demanded::Available { .. }
        ));
        assert!(matches!(
            host.demand::<RustUnitDependents>(analyzer, &read, &[0; 32]),
            Demanded::Available { .. }
        ));
        assert!(matches!(
            host.demand::<RustFileUnits>(analyzer, &read, &"src/missing.rs".to_string()),
            Demanded::Available { .. }
        ));
        assert!(matches!(
            host.demand::<RustCrateNameUnits>(analyzer, &read, &"missing".to_string()),
            Demanded::Available { .. }
        ));
        assert!(matches!(
            host.demand::<RustPackageUnits>(analyzer, &read, &"missing".to_string()),
            Demanded::Available { .. }
        ));
        let units = match host.demand::<RustFileUnits>(analyzer, &read, &"src/lib.rs".to_string()) {
            Demanded::Available {
                value, complete, ..
            } => {
                assert!(complete);
                value
            }
            Demanded::Unavailable(cause) => panic!("membership: {cause:?}"),
        };
        // An absent unit token is valid stratum-zero evidence, but it cannot
        // certify an empty route fragment or composed reachability answer.
        let absent = SelectedRustUnit::minted_by_test_fixture([0; 32]);
        assert!(!matches!(
            host.demand::<RustUnitRoutes>(analyzer, &read, &absent),
            Demanded::Available { complete: true, .. }
        ));
        assert!(!matches!(
            host.demand::<RustTargetReachability>(analyzer, &read, &absent),
            Demanded::Available { complete: true, .. }
        ));
        let unit = &units[0];
        assert!(matches!(
            host.demand::<RustUnitRoutes>(analyzer, &read, unit),
            Demanded::Available { complete: true, .. }
        ));
        assert!(matches!(
            host.demand::<RustTargetReachability>(analyzer, &read, unit),
            Demanded::Available { complete: true, .. }
        ));
    }
}
