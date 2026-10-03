//! The structured proof behind a Java single-type import whose path has more
//! than one package-prefix split.
//!
//! `import bench.mod00000.Module00000;` can be read two ways:
//!
//! * package `bench` with the nested type route `mod00000.Module00000`, or
//! * package `bench.mod00000` with the top-level type `Module00000`.
//!
//! Both readings render to the same dotted name, so a lookup keyed on the
//! rendered name cannot tell them apart: whichever declaration the index lists
//! first wins, and the choice is a store-order accident rather than a
//! resolution.
//!
//! This module decides the split from structure instead. An [`FqName`] records
//! which of its segments denote a namespace and which denote a type, so the
//! two readings are distinguishable, and each reading names a package prefix to
//! ask the caller's inventory about. The proof accepts a split only when it
//! reaches exactly one top-level type and *every* other split is closed: its
//! package inventory is exhaustive and the first segment after that package has
//! no top-level owner. A nested match, several matches, an owner that can
//! contribute an inherited nested type, an inventory that cannot prove absence,
//! and a path with no package segment at all leave the proof open. An open
//! proof keeps every reading: a caller that reports ambiguity reads them all,
//! and a caller that needs the legacy single answer reads the first.
//!
//! The theorem is deliberately independent of legacy-compatible public output:
//! it decides what the import tiers may claim, and callers that only need the
//! old best-effort answer keep reading [`JavaSingleTypeImportProof::targets`].
//!
//! [`FqName`]: brokk_bifrost_core::analyzer::fq_name::FqName

use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::fq_name::{SegmentKind, segment_interner};

/// Why a single-type import did not reduce to exactly one proven
/// package-prefix split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JavaImportSplitGap {
    /// The import path has no package segment before its terminal name, so
    /// there is no split to prove.
    NoPackagePrefix,
    /// No split of the path reaches a top-level type.
    MissingDestination,
    /// One split holds more than one top-level type under the terminal name.
    /// A mirrored source tree produces this with one repeated shape, so the
    /// tier keeps the index's ordered first pick while the proof stays open.
    MultipleMatches,
    /// Every match descends through a nested type. The path is readable, but
    /// no split's *top-level* destination was reached, so another reading
    /// stays possible.
    NestedOnlyMatch,
    /// A shallower split's first post-package segment has a top-level owner.
    /// That owner can still carry the rest of the route as an inherited nested
    /// type, so the split cannot be closed.
    AlternativeFirstSegmentOwner,
    /// The caller's inventory cannot answer exhaustively for a package, so an
    /// empty answer is a miss rather than a proof of absence.
    IncompleteAlternativeInventory,
}

/// What the package-prefix splits of one Java single-type import prove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JavaSingleTypeImportProof {
    /// Exactly one split reaches exactly one top-level type, and every other
    /// split is closed. The import binds that declaration and nothing else.
    Proven(CodeUnit),
    /// No split is proven. `targets` holds every reading of the path the
    /// inventory indexes, replacing-readings first: the exact top-level split
    /// leads, then the nested readings, then any declaration the rendered
    /// lookup returns that is not a reading of this path at all. The list is
    /// what the legacy tiers offered as one arbitrary pick.
    Open {
        gap: JavaImportSplitGap,
        targets: Vec<CodeUnit>,
    },
}

impl JavaSingleTypeImportProof {
    /// The proof's one binding, or the strongest reading when no split is
    /// proven.
    pub fn single_target(&self) -> Option<CodeUnit> {
        match self {
            Self::Proven(unit) => Some(unit.clone()),
            Self::Open { targets, .. } => targets.first().cloned(),
        }
    }

    /// Every reading this proof keeps, strongest first.
    pub fn targets(&self) -> Vec<CodeUnit> {
        match self {
            Self::Proven(unit) => vec![unit.clone()],
            Self::Open { targets, .. } => targets.clone(),
        }
    }

    /// The typed reason the proof stayed open, or `None` when it is proven.
    pub fn gap(&self) -> Option<JavaImportSplitGap> {
        match self {
            Self::Proven(_) => None,
            Self::Open { gap, .. } => Some(*gap),
        }
    }
}

/// The declaration inventory one split proof reads.
///
/// The inventory answers one question: every class indexed under a rendered
/// dotted name. It also states whether an empty answer is a proof of absence,
/// because closing an alternative split is exactly that claim.
#[derive(Clone, Copy)]
pub struct JavaImportInventory<'a> {
    classes_at: &'a dyn Fn(&str) -> Vec<CodeUnit>,
    exhaustive: bool,
}

impl<'a> JavaImportInventory<'a> {
    /// An inventory that indexes every declaration it can name, so an empty
    /// answer proves that no such top-level type exists. A workspace index
    /// with a complete symbol lookup is this case.
    pub fn exhaustive(classes_at: &'a dyn Fn(&str) -> Vec<CodeUnit>) -> Self {
        Self {
            classes_at,
            exhaustive: true,
        }
    }

    /// An inventory that may be bounded, budgeted, suppressed or scoped to one
    /// language, so an empty answer only means it did not find one. Every
    /// alternative split stays open.
    pub fn partial(classes_at: &'a dyn Fn(&str) -> Vec<CodeUnit>) -> Self {
        Self {
            classes_at,
            exhaustive: false,
        }
    }

    /// Every class the inventory indexes under `name`.
    pub fn classes_at(&self, name: &str) -> Vec<CodeUnit> {
        (self.classes_at)(name)
    }
}

/// Prove the package-prefix split of the single-type import `path`.
///
/// `path` is the import's segments with the terminal type name last, exactly
/// as the parser recorded them. The caller has already established that this
/// is a non-static single-type import (no `*`).
pub fn prove_java_single_type_import(
    path: &[String],
    inventory: JavaImportInventory<'_>,
) -> JavaSingleTypeImportProof {
    assert!(
        !path.is_empty(),
        "a single-type import path has at least one segment"
    );
    let readings = ImportReadings::of(path, inventory.classes_at(&path.join(".")));
    let targets = readings.readings();

    if path.len() < 2 {
        return open(JavaImportSplitGap::NoPackagePrefix, targets);
    }
    if readings.top_level.is_empty() {
        let gap = if readings.nested.is_empty() {
            JavaImportSplitGap::MissingDestination
        } else {
            JavaImportSplitGap::NestedOnlyMatch
        };
        return open(gap, targets);
    }
    if readings.top_level.len() > 1 {
        return open(JavaImportSplitGap::MultipleMatches, targets);
    }
    if !readings.nested.is_empty() {
        return open(JavaImportSplitGap::AlternativeFirstSegmentOwner, targets);
    }

    // Every shallower split reads the path as a package prefix followed by a
    // nested type route. Such a split is closed only when the first segment
    // after its package has no top-level owner at all: with an owner, an
    // inherited nested type can still satisfy the route, and an inheritance
    // the inventory does not hold is not an inheritance it can rule out.
    for prefix_len in 1..path.len() - 1 {
        if !inventory.exhaustive {
            return open(JavaImportSplitGap::IncompleteAlternativeInventory, targets);
        }
        let prefix = &path[..=prefix_len];
        let owner = ImportReadings::of(prefix, inventory.classes_at(&prefix.join(".")));
        if !owner.top_level.is_empty() {
            return open(JavaImportSplitGap::AlternativeFirstSegmentOwner, targets);
        }
    }

    JavaSingleTypeImportProof::Proven(
        readings
            .top_level
            .into_iter()
            .next()
            .expect("a proven split holds exactly one top-level type"),
    )
}

fn open(gap: JavaImportSplitGap, targets: Vec<CodeUnit>) -> JavaSingleTypeImportProof {
    JavaSingleTypeImportProof::Open { gap, targets }
}

/// The classes one inventory indexes under a rendered name, partitioned by how
/// each one reads the path that name was rendered from.
#[derive(Default)]
struct ImportReadings {
    /// Classes reading the whole path as package segments plus a terminal
    /// type: the split at the last segment.
    top_level: Vec<CodeUnit>,
    /// Classes reading a strict prefix as package segments and the rest as a
    /// nested type route: every shallower split, including the unnamed
    /// package's leading-type route.
    nested: Vec<CodeUnit>,
    /// Classes the inventory rendered under the name whose segment kinds are
    /// no reading of this path. They cannot prove anything, but a caller
    /// answering a rendered-name lookup still sees them.
    other: Vec<CodeUnit>,
}

impl ImportReadings {
    fn of(path: &[String], classes: Vec<CodeUnit>) -> Self {
        let interner = segment_interner();
        let mut readings = Self::default();
        for unit in classes {
            if !unit.is_class() {
                continue;
            }
            let fq = unit.fq();
            if fq.len() != path.len() {
                readings.other.push(unit);
                continue;
            }
            let segments = fq.segments();
            let texts_match = segments
                .iter()
                .zip(path)
                .all(|(&id, text)| interner.resolve(id).0 == text);
            if !texts_match {
                readings.other.push(unit);
                continue;
            }
            let namespace_len = segments
                .iter()
                .take_while(|&&id| interner.resolve(id).1.denotes_namespace())
                .count();
            if namespace_len == path.len() {
                readings.other.push(unit);
                continue;
            }
            let route_is_types = segments[namespace_len..]
                .iter()
                .all(|&id| denotes_type_segment(interner.resolve(id).1));
            if !route_is_types {
                readings.other.push(unit);
                continue;
            }
            if namespace_len == path.len() - 1 {
                readings.top_level.push(unit);
            } else {
                readings.nested.push(unit);
            }
        }
        readings
    }

    /// Every reading, replacing-readings first, one candidate per distinct
    /// segment-kind shape.
    ///
    /// A mirrored source tree indexes the same qualified name more than once
    /// with the same shape, and the index already orders those rows; collapsing
    /// them keeps the tier's legacy first pick and its same-file preference
    /// (#2045). Distinct shapes are distinct readings of the canonical name,
    /// and each of them stays a peer.
    fn readings(&self) -> Vec<CodeUnit> {
        let mut all: Vec<CodeUnit> = Vec::new();
        for unit in self
            .top_level
            .iter()
            .chain(self.nested.iter())
            .chain(self.other.iter())
        {
            let shape = unit.fq().segments().to_vec();
            let seen = all
                .iter()
                .any(|kept| kept.fq().segments() == shape.as_slice());
            if !seen {
                all.push(unit.clone());
            }
        }
        all
    }
}

/// Whether a segment kind can spell a type inside a canonical name's type
/// route. `Member` and `Unknown` cannot: a member is not a type, and an
/// unclaimed kind is not a claim this proof may read.
fn denotes_type_segment(kind: SegmentKind) -> bool {
    matches!(
        kind,
        SegmentKind::Type | SegmentKind::Nested | SegmentKind::Companion
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::fq_name::{FqName, segment_interner};
    use brokk_bifrost_core::analyzer::model::CodeUnitType;
    use std::collections::HashMap;
    use std::path::PathBuf;

    /// One declaration in a fake inventory, written as its segment kinds.
    #[derive(Clone, Copy, Debug)]
    enum Shape {
        Package,
        Type,
    }

    use Shape::{Package, Type};

    struct FakeInventory {
        classes: HashMap<String, Vec<CodeUnit>>,
    }

    /// `ProjectFile::new` asserts an absolute root, and a leading-slash path is
    /// relative on Windows, so spell the fixture root for the host.
    fn absolute_root() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\java-split-proof")
        } else {
            PathBuf::from("/java-split-proof")
        }
    }

    impl FakeInventory {
        fn new(declarations: &[&[(&str, Shape)]]) -> Self {
            let mut classes: HashMap<String, Vec<CodeUnit>> = HashMap::new();
            for (index, path) in declarations.iter().enumerate() {
                let interner = segment_interner();
                let mut fq = FqName::new();
                for (text, shape) in path.iter() {
                    let kind = match shape {
                        Shape::Package => SegmentKind::Package,
                        Shape::Type => SegmentKind::Type,
                    };
                    fq.push(interner.intern(text, kind));
                }
                let package_len = path
                    .iter()
                    .take_while(|(_, shape)| matches!(shape, Shape::Package))
                    .count();
                let file = ProjectFile::new(
                    absolute_root(),
                    PathBuf::from(format!("src/Generated{index}.java")),
                );
                let unit =
                    CodeUnit::from_fq(file, CodeUnitType::Class, fq, package_len, None, false);
                classes.entry(unit.fq_name()).or_default().push(unit);
            }
            Self { classes }
        }

        fn classes_at(&self, name: &str) -> Vec<CodeUnit> {
            self.classes.get(name).cloned().unwrap_or_default()
        }
    }

    /// The segment kinds of one target, so a test can tell the two readings of
    /// one rendered name apart.
    fn shapes(unit: &CodeUnit) -> Vec<(&'static str, SegmentKind)> {
        let interner = segment_interner();
        unit.fq()
            .segments()
            .iter()
            .map(|&id| interner.resolve(id))
            .collect()
    }

    fn target_shapes(proof: &JavaSingleTypeImportProof) -> Vec<Vec<SegmentKind>> {
        proof
            .targets()
            .iter()
            .map(|unit| {
                unit.fq()
                    .segments()
                    .iter()
                    .map(|&id| segment_interner().resolve(id).1)
                    .collect()
            })
            .collect()
    }

    fn import_path(segments: &[&str]) -> Vec<String> {
        segments.iter().map(|segment| segment.to_string()).collect()
    }

    fn prove(inventory: &FakeInventory, path: &[&str]) -> JavaSingleTypeImportProof {
        let classes_at = |name: &str| inventory.classes_at(name);
        prove_java_single_type_import(
            &import_path(path),
            JavaImportInventory::exhaustive(&classes_at),
        )
    }

    fn prove_partial(inventory: &FakeInventory, path: &[&str]) -> JavaSingleTypeImportProof {
        let classes_at = |name: &str| inventory.classes_at(name);
        prove_java_single_type_import(
            &import_path(path),
            JavaImportInventory::partial(&classes_at),
        )
    }

    #[test]
    fn two_prefix_import_proves_the_exact_top_level_split() {
        let inventory = FakeInventory::new(&[&[
            ("bench", Package),
            ("mod00000", Package),
            ("Module00000", Type),
        ]]);
        let proof = prove(&inventory, &["bench", "mod00000", "Module00000"]);
        assert_eq!(proof.gap(), None);
        let JavaSingleTypeImportProof::Proven(unit) = &proof else {
            panic!("a closed split is proven: {proof:?}");
        };
        assert_eq!(unit.fq_name(), "bench.mod00000.Module00000");
        assert_eq!(
            shapes(unit),
            vec![
                ("bench", SegmentKind::Package),
                ("mod00000", SegmentKind::Package),
                ("Module00000", SegmentKind::Type),
            ]
        );
    }

    #[test]
    fn an_alternative_first_segment_owner_keeps_the_split_open() {
        let inventory = FakeInventory::new(&[
            &[("bench", Package), ("mod00000", Type)],
            &[
                ("bench", Package),
                ("mod00000", Package),
                ("Module00000", Type),
            ],
        ]);
        let proof = prove(&inventory, &["bench", "mod00000", "Module00000"]);
        assert_eq!(
            proof.gap(),
            Some(JavaImportSplitGap::AlternativeFirstSegmentOwner)
        );
        assert_eq!(
            target_shapes(&proof),
            vec![vec![
                SegmentKind::Package,
                SegmentKind::Package,
                SegmentKind::Type
            ]],
            "the owner closes the alternative without replacing the exact split"
        );
    }

    #[test]
    fn a_nested_reading_of_the_same_name_joins_the_exact_split() {
        let inventory = FakeInventory::new(&[
            &[
                ("bench", Package),
                ("mod00000", Type),
                ("Module00000", Type),
            ],
            &[
                ("bench", Package),
                ("mod00000", Package),
                ("Module00000", Type),
            ],
        ]);
        let proof = prove(&inventory, &["bench", "mod00000", "Module00000"]);
        assert_eq!(
            proof.gap(),
            Some(JavaImportSplitGap::AlternativeFirstSegmentOwner)
        );
        assert_eq!(
            target_shapes(&proof),
            vec![
                vec![
                    SegmentKind::Package,
                    SegmentKind::Package,
                    SegmentKind::Type
                ],
                vec![SegmentKind::Package, SegmentKind::Type, SegmentKind::Type],
            ],
            "the exact top-level split leads the nested reading of the same name"
        );
    }

    #[test]
    fn a_nested_only_reading_stays_open() {
        let inventory = FakeInventory::new(&[&[
            ("bench", Package),
            ("mod00000", Type),
            ("Module00000", Type),
        ]]);
        let proof = prove(&inventory, &["bench", "mod00000", "Module00000"]);
        assert_eq!(proof.gap(), Some(JavaImportSplitGap::NestedOnlyMatch));
        assert_eq!(
            target_shapes(&proof),
            vec![vec![
                SegmentKind::Package,
                SegmentKind::Type,
                SegmentKind::Type
            ]]
        );
    }

    #[test]
    fn several_top_level_matches_stay_open() {
        let inventory = FakeInventory::new(&[
            &[
                ("bench", Package),
                ("mod00000", Package),
                ("Module00000", Type),
            ],
            &[
                ("bench", Package),
                ("mod00000", Package),
                ("Module00000", Type),
            ],
        ]);
        let proof = prove(&inventory, &["bench", "mod00000", "Module00000"]);
        assert_eq!(proof.gap(), Some(JavaImportSplitGap::MultipleMatches));
        assert_eq!(
            target_shapes(&proof),
            vec![vec![
                SegmentKind::Package,
                SegmentKind::Package,
                SegmentKind::Type
            ]],
            "a mirrored tree repeats one shape, so the tier keeps its ordered first pick"
        );
    }

    /// A bounded, budgeted or cancelled lookup truncates its rows instead of
    /// failing, so its empty answer is a miss and never a proof of absence.
    #[test]
    fn a_partial_inventory_cannot_close_an_alternative_split() {
        let inventory = FakeInventory::new(&[&[
            ("bench", Package),
            ("mod00000", Package),
            ("Module00000", Type),
        ]]);
        assert_eq!(
            prove(&inventory, &["bench", "mod00000", "Module00000"]).gap(),
            None
        );
        assert_eq!(
            prove_partial(&inventory, &["bench", "mod00000", "Module00000"]).gap(),
            Some(JavaImportSplitGap::IncompleteAlternativeInventory)
        );
        let lone = FakeInventory::new(&[&[("bench", Package), ("Module00000", Type)]]);
        assert_eq!(
            prove_partial(&lone, &["bench", "Module00000"]).gap(),
            None,
            "a lone split needs no absence proof"
        );

        // A lookup that stops before answering at all leaves the proof with no
        // destination either, so the caller resolves nothing rather than
        // closing the route on a truncated result.
        let truncated = FakeInventory::new(&[]);
        let proof = prove_partial(&truncated, &["bench", "mod00000", "Module00000"]);
        assert_eq!(proof.gap(), Some(JavaImportSplitGap::MissingDestination));
        assert!(proof.targets().is_empty());
    }

    #[test]
    fn a_missing_destination_stays_open_with_no_target() {
        let inventory = FakeInventory::new(&[]);
        let proof = prove(&inventory, &["bench", "mod00000", "Module00000"]);
        assert_eq!(proof.gap(), Some(JavaImportSplitGap::MissingDestination));
        assert!(proof.targets().is_empty());
        assert_eq!(proof.single_target(), None);
    }

    #[test]
    fn a_path_without_a_package_segment_is_not_a_split() {
        let inventory = FakeInventory::new(&[]);
        let proof = prove(&inventory, &["Module00000"]);
        assert_eq!(proof.gap(), Some(JavaImportSplitGap::NoPackagePrefix));
    }
}
