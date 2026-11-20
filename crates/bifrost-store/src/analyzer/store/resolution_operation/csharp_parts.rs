//! Dormant C# partial-type part groups, assembled at demand time.
//!
//! Each part of a partial type is already an ordinary per-file declaration:
//! its own modifier row, member scope and namespace member. Nothing cross-file
//! is persisted. A group is the set of declarations of one type inside one
//! compilation placement, keyed by (namespace path, nesting path, name with
//! generic arity). The producer folds arity into the declared name
//! ("Name`2"), so equal name-lookup identity is equal name and arity.
//!
//! Top-level parts come from the name-first namespace reader, filtered to the
//! placement's own compilation. Nested parts are the same-named nested-type
//! members of every enclosing part, so two parts of one type in one file and
//! parts in several files are the same case. Placement groups combine by
//! agreement: equal groups agree, differing or unproven groups are open.
use super::csharp_namespaces::{CSharpNamespaceLevel, namespace_types_for_lookup};
use super::csharp_units::{CSharpUnitPlacement, CSharpUnitReader};
use super::package_context::SelectedPackageRows;
use super::*;
use crate::analyzer::resolution::ResolutionLookupSemanticRecipe;
use crate::analyzer::store::WorkspaceSnapshotId;
use crate::analyzer::store::selected_read::SelectedRead;
use crate::analyzer::store::selected_read::queries::csharp::{
    CSharpDeclarationFactsRead, CSharpDeclarationKey, CSharpNamespaceRouteRead,
    CSharpNamespaceScopeKey, CSharpNestedTypeKey, CSharpNestedTypeRead,
};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

/// One declaration of a type: a single part of a partial type, or the whole of
/// a non-partial one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CSharpPart {
    pub mount: SelectedResolutionMountOrdinal,
    pub path: String,
    pub definition: SemanticId,
    /// None is a missing modifier row, distinct from a proven non-partial type.
    pub partial: Option<bool>,
}

/// Why declarations sharing one group key do not merge into one type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CSharpPartConflict {
    /// More than one declaration shares the key and one is not partial (CS0101).
    DuplicateNonPartial,
    /// A declaration lacks its modifier row, so its partiality is unproven.
    UnprovenPartial,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CSharpPartShape {
    /// One declaration, proven non-partial: a complete group on its own.
    Singleton,
    /// Every declaration is proven partial: they merge into one type.
    Partial,
    /// Consumers fail closed: the declarations are not a mergeable group.
    Conflicted(CSharpPartConflict),
}

/// The part group of one type in one compilation placement.
#[derive(Clone, Debug)]
pub struct CSharpPartGroup {
    pub placement: CSharpUnitPlacement,
    pub shape: CSharpPartShape,
    /// Ordered by path, then by declaration. Empty only when the anchor is open.
    pub parts: Vec<CSharpPart>,
    /// Complete when every candidate file's placement membership is proven.
    pub completion: ResolutionCompletion,
}

#[derive(Clone, Debug)]
pub enum CSharpPartAgreement {
    /// Every placement proved the same group: this is the complete answer.
    Agreed {
        shape: CSharpPartShape,
        parts: Vec<CSharpPart>,
    },
    /// Unproven membership, no placement, or placements that disagree.
    Open(ResolutionCompletion),
}

#[derive(Clone, Debug)]
pub struct CSharpPartGroups {
    /// One group for each compilation placement of the anchor's own file.
    pub per_placement: Vec<CSharpPartGroup>,
    pub agreement: CSharpPartAgreement,
}

struct TypeIdentity {
    lookup: SemanticId,
    namespace: Vec<String>,
    /// Member names from the outermost type's nested type inward.
    nesting: Vec<String>,
    /// The outermost enclosing declaration of the anchor.
    outermost: SemanticId,
}

fn local_key(definition: SemanticId) -> Option<(u32, u32)> {
    Some((definition.ordinal()?, definition.local_key()?))
}

fn mount_content(
    ready: &ReadySelectedResolution<'_, '_>,
    read: &SelectedRead<'_>,
    ordinal: u32,
) -> Result<
    Option<(
        crate::analyzer::store::selected_read::RecordedContent,
        String,
    )>,
> {
    let record = ready
        .inventory
        .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    let path = record.persisted_relative_path().to_owned();
    Ok(read
        .mount_by_path(Language::CSharp, &path)?
        .map(|content| (content, path)))
}

/// Name the anchor by its enclosing declarations, up to its namespace.
fn identify(
    ready: &ReadySelectedResolution<'_, '_>,
    read: &SelectedRead<'_>,
    anchor: SemanticId,
    cancellation: &CancellationToken,
) -> Result<Option<Option<TypeIdentity>>> {
    let mut current = anchor;
    let mut nesting = Vec::new();
    // Nesting is bounded by the source; this only guards corrupt owner cycles.
    for _ in 0..256 {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some((ordinal, key)) = local_key(current) else {
            return Ok(Some(None));
        };
        let Some((content, _)) = mount_content(ready, read, ordinal)? else {
            return Ok(Some(None));
        };
        let facts = read.selection::<CSharpDeclarationFactsRead>(&CSharpDeclarationKey {
            content,
            definition: key,
        })?;
        if let Some((owner, name)) = facts.nested_in {
            nesting.push(name);
            current = SemanticId::local(ordinal, owner);
            continue;
        }
        let SelectedPackageRows::Ready(by_lookup) = ready.selected_package_members_by_lookup(
            SelectedResolutionMountOrdinal::new(ordinal),
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let Some((lookup, member)) = by_lookup.iter().find_map(|(lookup, members)| {
            members
                .iter()
                .find(|member| {
                    member.definition == current && member.namespace == ResolutionNamespace::Type
                })
                .map(|member| (*lookup, *member))
        }) else {
            return Ok(Some(None));
        };
        let Some(scope) = member.root_scope.local_key() else {
            return Ok(Some(None));
        };
        let (content, _) = mount_content(ready, read, ordinal)?
            .ok_or_else(|| StoreError::corrupt("C# part anchor mount vanished"))?;
        let Some(namespace) = read
            .selection::<CSharpNamespaceRouteRead>(&CSharpNamespaceScopeKey { content, scope })?
        else {
            return Ok(Some(None));
        };
        nesting.reverse();
        return Ok(Some(Some(TypeIdentity {
            lookup,
            namespace,
            nesting,
            outermost: current,
        })));
    }
    Err(StoreError::corrupt("C# nested type owners form a cycle"))
}

fn shape_of(parts: &[CSharpPart]) -> CSharpPartShape {
    if parts.len() > 1 && parts.iter().any(|part| part.partial == Some(false)) {
        CSharpPartShape::Conflicted(CSharpPartConflict::DuplicateNonPartial)
    } else if parts.iter().any(|part| part.partial.is_none()) {
        CSharpPartShape::Conflicted(CSharpPartConflict::UnprovenPartial)
    } else if parts.len() == 1 && parts[0].partial == Some(false) {
        CSharpPartShape::Singleton
    } else {
        CSharpPartShape::Partial
    }
}

fn open_reason(
    ready: &ReadySelectedResolution<'_, '_>,
    name: &'static str,
    parts: &[&str],
    evidence: String,
) -> ResolutionCompletion {
    let mut hash = CanonicalHasher::new(b"csharp-part-group-open:v1");
    hash.field("name", name.as_bytes());
    hash.field("scope", &ready.inventory.scope_identity());
    for part in parts {
        hash.field("part", part.as_bytes());
    }
    hash.field("evidence", evidence.as_bytes());
    let reason = ready.context_identities.named_semantic(
        hash.finish(),
        name,
        crate::analyzer::resolution::ReasonDeterminism::Unaudited,
        &evidence,
    );
    ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(reason)])
}

fn sort_parts(parts: &mut [CSharpPart]) {
    parts.sort_by(|a, b| {
        (a.path.as_str(), a.definition.get()).cmp(&(b.path.as_str(), b.definition.get()))
    });
}

struct PartReader<'a, 'unit, 'store, 'input> {
    ready: &'unit ReadySelectedResolution<'store, 'input>,
    units: &'a RefCell<CSharpUnitReader<'unit, 'store>>,
    read: &'a SelectedRead<'unit>,
    identity: &'a TypeIdentity,
    source: BindingFragmentId,
    cancellation: &'a CancellationToken,
}

impl PartReader<'_, '_, '_, '_> {
    /// The group in one compilation placement. None is cancellation.
    fn group(&self, placement: &CSharpUnitPlacement) -> Result<Option<CSharpPartGroup>> {
        let ready = self.ready;
        let level = CSharpNamespaceLevel {
            caller: placement.clone(),
            path: self.identity.namespace.clone(),
        };
        let SelectedPackageRows::Ready(admitted) = namespace_types_for_lookup(
            ready,
            self.units,
            self.source,
            &level,
            self.identity.lookup,
            self.cancellation,
        )?
        else {
            return Ok(None);
        };
        let mut completion = ResolutionCompletion::Complete;
        let mut unproven = Vec::new();
        let mut level_parts = Vec::new();
        let mut seen = HashSet::default();
        for candidate in admitted {
            if candidate.member.namespace != ResolutionNamespace::Type
                || !seen.insert(candidate.member.definition)
            {
                continue;
            }
            let record = ready.inventory.mount_record_by_ordinal(candidate.mount)?;
            let path = record.persisted_relative_path().to_owned();
            // Parts share a compilation, not merely visibility.
            match self.units.borrow_mut().placements(&path)? {
                Some(placements) => {
                    if !placements
                        .iter()
                        .any(|other| other.compilation_id == placement.compilation_id)
                    {
                        continue;
                    }
                }
                None => unproven.push(path.clone()),
            }
            completion = completion.combine(&candidate.completion);
            let Some((content, _)) = mount_content(ready, self.read, candidate.mount.get())? else {
                return Err(StoreError::corrupt(
                    "C# part candidate mount has no content",
                ));
            };
            let Some(key) = candidate.member.definition.local_key() else {
                return Err(StoreError::corrupt("C# part candidate is not mount-local"));
            };
            let facts =
                self.read
                    .selection::<CSharpDeclarationFactsRead>(&CSharpDeclarationKey {
                        content,
                        definition: key,
                    })?;
            level_parts.push(CSharpPart {
                mount: candidate.mount,
                path,
                definition: candidate.member.definition,
                partial: facts.partial,
            });
        }
        if !unproven.is_empty() {
            unproven.sort_unstable();
            unproven.dedup();
            completion = completion.combine(&open_reason(
                ready,
                "csharp_part_membership_unproven",
                &unproven.iter().map(String::as_str).collect::<Vec<_>>(),
                format!("compilation membership of {unproven:?} is unproven"),
            ));
        }
        sort_parts(&mut level_parts);
        let mut shape = shape_of(&level_parts);
        let mut parts = level_parts;
        if !parts
            .iter()
            .any(|part| part.definition == self.identity.outermost)
        {
            completion = completion.combine(&open_reason(
                ready,
                "csharp_part_anchor_absent",
                &[],
                format!(
                    "the enclosing declaration is not a part in compilation {:?}",
                    placement.project_path
                ),
            ));
        }
        for name in &self.identity.nesting {
            let mut next = Vec::new();
            let mut mounts: Vec<_> = parts.iter().map(|part| part.mount).collect();
            mounts.sort_unstable();
            mounts.dedup();
            for mount in mounts {
                if self.cancellation.is_cancelled() {
                    return Ok(None);
                }
                let owners: Vec<u32> = parts
                    .iter()
                    .filter(|part| part.mount == mount)
                    .filter_map(|part| part.definition.local_key())
                    .collect();
                let Some((content, path)) = mount_content(ready, self.read, mount.get())? else {
                    return Err(StoreError::corrupt("C# part mount has no content"));
                };
                let rows = self
                    .read
                    .selection::<CSharpNestedTypeRead>(&CSharpNestedTypeKey {
                        content,
                        owners: owners.into_boxed_slice(),
                        name: name.as_str().into(),
                    })?;
                for row in rows {
                    next.push(CSharpPart {
                        mount,
                        path: path.clone(),
                        definition: SemanticId::local(mount.get(), row.definition),
                        partial: row.partial,
                    });
                }
            }
            sort_parts(&mut next);
            // A conflicted enclosing group keeps its conflict for its members.
            let nested = shape_of(&next);
            if !matches!(shape, CSharpPartShape::Conflicted(_)) {
                shape = nested;
            }
            parts = next;
        }
        Ok(Some(CSharpPartGroup {
            placement: placement.clone(),
            shape,
            parts,
            completion,
        }))
    }
}

fn agree(
    ready: &ReadySelectedResolution<'_, '_>,
    groups: &[CSharpPartGroup],
) -> CSharpPartAgreement {
    let Some(first) = groups.first() else {
        return CSharpPartAgreement::Open(open_reason(
            ready,
            "csharp_part_placement_unproven",
            &[],
            "the declaration's compilation membership is unproven".to_owned(),
        ));
    };
    let mut open = ResolutionCompletion::Complete;
    for group in groups {
        open = open.combine(&group.completion);
    }
    if !matches!(open, ResolutionCompletion::Complete) {
        return CSharpPartAgreement::Open(open);
    }
    if groups
        .iter()
        .any(|group| group.shape != first.shape || group.parts != first.parts)
    {
        let described: Vec<_> = groups
            .iter()
            .map(|group| {
                (
                    &group.placement.project_path,
                    &group.placement.target_framework,
                    group
                        .parts
                        .iter()
                        .map(|p| p.path.as_str())
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        return CSharpPartAgreement::Open(open_reason(
            ready,
            "csharp_part_groups_disagree",
            &[],
            format!("compilation placements disagree on the part group: {described:?}"),
        ));
    }
    CSharpPartAgreement::Agreed {
        shape: first.shape,
        parts: first.parts.clone(),
    }
}

/// Assemble the part groups of the type declared at `anchor` in every
/// compilation placement of its file, then combine them by agreement. None is
/// cancellation or an operation without analyzer services to record the reads.
pub fn read_part_groups<'unit, 'store, 'input>(
    ready: &'unit ReadySelectedResolution<'store, 'input>,
    units: &RefCell<CSharpUnitReader<'unit, 'store>>,
    anchor: SemanticId,
    cancellation: &CancellationToken,
) -> Result<Option<CSharpPartGroups>> {
    let Some(services) = ready.analyzer else {
        return Ok(None);
    };
    let read = SelectedRead::new(ready, services);
    let Some(identity) = identify(ready, &read, anchor, cancellation)? else {
        return Ok(None);
    };
    let Some((ordinal, _)) = local_key(anchor) else {
        return Ok(Some(open_groups(
            ready,
            "anchor is not a selected declaration",
        )));
    };
    let Some(identity) = identity else {
        return Ok(Some(open_groups(
            ready,
            "the declaration is not a type with a namespace identity",
        )));
    };
    let record = ready
        .inventory
        .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    let Some(placements) = units
        .borrow_mut()
        .placements(record.persisted_relative_path())?
    else {
        return Ok(Some(open_groups(
            ready,
            "the declaration's compilation membership is unproven",
        )));
    };
    let reader = PartReader {
        ready,
        units,
        read: &read,
        identity: &identity,
        source: record.fragment_id(),
        cancellation,
    };
    let mut groups = Vec::new();
    for placement in &placements {
        let Some(group) = reader.group(placement)? else {
            return Ok(None);
        };
        groups.push(group);
    }
    let agreement = agree(ready, &groups);
    Ok(Some(CSharpPartGroups {
        per_placement: groups,
        agreement,
    }))
}

fn open_groups(ready: &ReadySelectedResolution<'_, '_>, why: &str) -> CSharpPartGroups {
    CSharpPartGroups {
        per_placement: Vec::new(),
        agreement: CSharpPartAgreement::Open(open_reason(
            ready,
            "csharp_part_anchor_unproven",
            &[],
            why.to_owned(),
        )),
    }
}

/// Exercise the dormant part reader on a type named structurally: `nesting[0]`
/// is a namespace-level type spelled as declared (arity as "Name`2"), later
/// entries are nested types. The first declaration of the last name in `path`'s
/// file is the anchor.
#[doc(hidden)]
pub fn probe_part_groups(
    operation: &SelectedResolutionOperation<'_, '_>,
    snapshot: &WorkspaceSnapshotId,
    path: &str,
    nesting: &[String],
    cancellation: &CancellationToken,
) -> Result<Option<CSharpPartGroups>> {
    let Some(mount) = operation.mount_table().mount_for_path("csharp", path)? else {
        return Ok(None);
    };
    let Some(certified) = operation.ready.certified_csharp_view()? else {
        return Ok(None);
    };
    let ready = &operation.ready;
    let Some(services) = ready.analyzer else {
        return Ok(None);
    };
    let read = SelectedRead::new(ready, services);
    let (first, rest) = nesting.split_first().expect("a type name");
    let names = ready.shared_names();
    let lookup =
        ResolutionLookupSemanticRecipe::new(Language::CSharp, ResolutionNamespace::Type, first)
            .semantic(&names);
    let SelectedPackageRows::Ready(members) =
        ready.selected_package_members_for_lookup(mount.ordinal(), lookup, cancellation)?
    else {
        return Ok(None);
    };
    let mut current: Vec<u32> = members
        .iter()
        .filter(|member| member.namespace == ResolutionNamespace::Type)
        .filter_map(|member| member.definition.local_key())
        .collect();
    current.sort_unstable();
    for name in rest {
        let Some((content, _)) = mount_content(ready, &read, mount.ordinal().get())? else {
            return Ok(None);
        };
        let rows = read.selection::<CSharpNestedTypeRead>(&CSharpNestedTypeKey {
            content,
            owners: current.clone().into_boxed_slice(),
            name: name.as_str().into(),
        })?;
        current = rows.into_iter().map(|row| row.definition).collect();
        current.sort_unstable();
    }
    let Some(&anchor) = current.first() else {
        return Ok(None);
    };
    let units = CSharpUnitReader::new(
        &ready.inventory,
        snapshot,
        &certified,
        &ready.context_identities,
        services,
    )?;
    let units = RefCell::new(units);
    read_part_groups(
        ready,
        &units,
        SemanticId::local(mount.ordinal().get(), anchor),
        cancellation,
    )
}
