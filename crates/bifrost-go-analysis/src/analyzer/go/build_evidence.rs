//! Files-only Go evidence projected into the shared #2442 contract.
//!
//! One bounded acquisition owns the returned rows. No workspace index, process,
//! disk read, semantic-pack production, or query-triggered discovery lives here.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::path::{Component, Path, PathBuf};

use brokk_bifrost_go::build_files::{
    BuildFileIssueKind, BuildFileLimits, GoBuildDocument, GoChecksumTarget, GoDirective,
    GoDirectiveEntry, parse_go_mod, parse_go_sum, parse_go_work, parse_vendor_modules,
};

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    DependencyCondition, DependencyEvidence, DependencyEvidenceGap, DependencyEvidenceGapKind,
    DependencyEvidenceKind, DependencyFileEvidence, DependencyFileEvidenceLimits,
    VersionComparator, parse_version_comparators, version_bounds_admit,
};

use brokk_bifrost_analysis::analyzer::topology::DependencyScope;

use brokk_bifrost_analysis::analyzer::topology::TopologyCompleteness;

use brokk_bifrost_analysis::analyzer::topology::TopologyEntity;

use brokk_bifrost_analysis::analyzer::topology::TopologyEntityKind;

use brokk_bifrost_analysis::analyzer::topology::TopologyProvenance;

use brokk_bifrost_analysis::analyzer::topology::TopologyProvenanceKind;

use brokk_bifrost_analysis::workspace_document::has_portable_windows_path_prefix;

use brokk_bifrost_analysis::workspace_document::validate_workspace_relative_path;

/// An exact, authorized snapshot supplied by the upstream store/acquisition.
/// Paths are workspace-relative; source may come from a committed or overlay
/// snapshot. The reader never falls back to the ambient disk.
#[derive(Debug, Clone, Copy)]
pub struct GoBuildSnapshot<'a> {
    pub path: &'a Path,
    pub source: &'a str,
    /// Blob identity of the selected snapshot's original bytes. Rows record
    /// it as their source digest, which the store checks against the
    /// retained input it presents.
    pub oid: git2::Oid,
}

/// Shared topology identity convention for a Go module's build project.
/// Internal ownership publication must use this same entity, not display names.
pub fn go_build_project(path: &Path, module: &str) -> TopologyEntity {
    TopologyEntity {
        kind: TopologyEntityKind::BuildProject,
        name: format!("go:{}:{module}", path.to_string_lossy().replace('\\', "/")),
        owner: None,
        root: Some(path.parent().expect("manifest has a parent").to_path_buf()),
        provenance: vec![TopologyProvenance::new(
            path,
            TopologyProvenanceKind::ProjectDeclaration,
        )],
        completeness: TopologyCompleteness::Complete,
    }
}

/// Shared topology identity convention for an explicitly supplied go.work.
pub fn go_build_workspace(path: &Path) -> TopologyEntity {
    TopologyEntity {
        kind: TopologyEntityKind::Workspace,
        name: format!("go:{}", path.to_string_lossy().replace('\\', "/")),
        owner: None,
        root: Some(
            path.parent()
                .expect("workspace manifest has parent")
                .to_path_buf(),
        ),
        provenance: vec![TopologyProvenance::new(
            path,
            TopologyProvenanceKind::ProjectDeclaration,
        )],
        completeness: TopologyCompleteness::Complete,
    }
}

struct DeclarationFile<'a> {
    snapshot: GoBuildSnapshot<'a>,
    document: GoBuildDocument,
    owner: Option<String>,
    digest: String,
}

/// Acquire declarations, checksum observations and unvalidated vendor rows.
/// Root requirements deliberately do not establish the complete MVS graph.
pub fn collect_go_build_evidence(
    snapshots: &[GoBuildSnapshot<'_>],
    limits: &DependencyFileEvidenceLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyFileEvidence {
    let cancelled = || cancellation.is_some_and(CancellationToken::is_cancelled);
    let mut result = DependencyFileEvidence::default();
    let parser_limits = BuildFileLimits {
        max_bytes: limits.max_file_bytes,
        max_tokens: limits.max_rows.saturating_mul(8).saturating_add(32),
        max_entries: limits.max_rows,
    };
    let mut declarations = HashMap::new();
    let mut integrity = Vec::new();
    let mut seen = HashSet::new();
    let mut attempted_files = 0;
    for snapshot in snapshots {
        let name = snapshot.path.file_name().and_then(|name| name.to_str());
        let vendor = snapshot.path.ends_with(Path::new("vendor/modules.txt"));
        if !matches!(name, Some("go.mod" | "go.work" | "go.sum" | "go.work.sum")) && !vendor {
            continue;
        }
        if cancelled() {
            gap(
                &mut result,
                snapshot.path,
                0..0,
                DependencyEvidenceGapKind::Cancelled,
                "Go acquisition cancelled",
            );
            break;
        }
        if attempted_files >= limits.max_files
            || snapshot.source.len() > limits.max_file_bytes
            || snapshot.source.len() > limits.max_total_bytes.saturating_sub(result.bytes_read)
        {
            gap(
                &mut result,
                snapshot.path,
                0..0,
                DependencyEvidenceGapKind::Limit,
                "Go build-file acquisition limit",
            );
            break;
        }
        // Rejected paths and duplicate snapshots still consume acquisition
        // work. Otherwise an arbitrarily long invalid input could bypass the
        // file bound and accumulate unbounded diagnostics.
        attempted_files += 1;
        let path = match validate_workspace_relative_path(snapshot.path) {
            Ok(path) if path == snapshot.path => path,
            _ => {
                gap(
                    &mut result,
                    snapshot.path,
                    0..0,
                    DependencyEvidenceGapKind::UnsafePath,
                    "Go snapshot path must be canonical and workspace-relative",
                );
                continue;
            }
        };
        if !seen.insert(path.clone()) {
            // Conflicting snapshots cannot make the first supplied file
            // authoritative, especially during vendor reconciliation.
            declarations.remove(&path);
            integrity.retain(|previous: &GoBuildSnapshot<'_>| previous.path != path);
            gap(
                &mut result,
                &path,
                0..0,
                DependencyEvidenceGapKind::Conflict,
                "Multiple snapshots supplied for one build file",
            );
            continue;
        }
        result.files_read += 1;
        result.bytes_read += snapshot.source.len();
        if name == Some("go.mod") || name == Some("go.work") {
            let document = if name == Some("go.mod") {
                parse_go_mod(snapshot.source, &parser_limits, cancelled)
            } else {
                parse_go_work(snapshot.source, &parser_limits, cancelled)
            };
            for error in &document.issues {
                syntax_gap(&mut result, &path, error.kind, error.range.clone());
            }
            let mut identities =
                document
                    .entries
                    .iter()
                    .filter_map(|entry| match &entry.directive {
                        GoDirective::Module(module) => Some(module.value.as_str()),
                        _ => None,
                    });
            let module = identities.next();
            let owner = if name == Some("go.work") {
                Some(go_build_workspace(&path).id())
            } else {
                module
                    .filter(|_| identities.next().is_none())
                    .map(|module| go_build_project(&path, module).id())
            };
            if owner.is_none() {
                gap(
                    &mut result,
                    &path,
                    0..0,
                    DependencyEvidenceGapKind::Unresolved,
                    "Module ownership requires exactly one valid module declaration",
                );
            }
            declarations.insert(
                path,
                DeclarationFile {
                    snapshot: *snapshot,
                    document,
                    owner,
                    digest: snapshot.oid.to_string(),
                },
            );
        } else {
            integrity.push(*snapshot);
        }
    }

    // Sort only this bounded acquisition's paths so order never selects a
    // workspace or changes row identity. Nothing survives the return.
    let mut paths: Vec<_> = declarations.keys().cloned().collect();
    paths.sort();
    for path in &paths {
        let file = &declarations[path];
        for entry in &file.document.entries {
            if cancelled() {
                gap(
                    &mut result,
                    path,
                    entry.range.clone(),
                    DependencyEvidenceGapKind::Cancelled,
                    "Go declaration projection cancelled",
                );
                return result;
            }
            if let Some(mut row) = declaration_row(file, entry) {
                apply_requirement_context(&mut row, file, &declarations);
                if !push_row(&mut result, row, limits) {
                    return result;
                }
            }
            match &entry.directive {
                GoDirective::Use(member) => {
                    let manifest =
                        relative_reference(path, &member.value).map(|root| root.join("go.mod"));
                    match manifest {
                        Some(manifest)
                            if declarations
                                .get(&manifest)
                                .is_some_and(|member| member.owner.is_some()) => {}
                        Some(_) => gap(
                            &mut result,
                            path,
                            member.range.clone(),
                            DependencyEvidenceGapKind::Missing,
                            "Workspace member has no supplied valid go.mod snapshot",
                        ),
                        None => gap(
                            &mut result,
                            path,
                            member.range.clone(),
                            DependencyEvidenceGapKind::UnsafePath,
                            "Workspace member is outside the authorized snapshot",
                        ),
                    }
                }
                GoDirective::Replace {
                    source,
                    local: true,
                    ..
                } => {
                    match relative_reference(path, &source.value).map(|root| root.join("go.mod")) {
                        Some(manifest)
                            if declarations
                                .get(&manifest)
                                .is_some_and(|replacement| replacement.owner.is_some()) => {}
                        Some(_) => gap(
                            &mut result,
                            path,
                            source.range.clone(),
                            DependencyEvidenceGapKind::Unresolved,
                            "Local replacement path retained; its version and module selection remain unknown",
                        ),
                        None => gap(
                            &mut result,
                            path,
                            source.range.clone(),
                            DependencyEvidenceGapKind::UnsafePath,
                            "Local replacement source is outside the supplied workspace snapshot",
                        ),
                    }
                }
                _ => {}
            }
        }
    }

    integrity.sort_by(|left, right| left.path.cmp(right.path));
    for snapshot in integrity {
        let path = snapshot.path;
        let digest = snapshot.oid.to_string();
        let parent = path.parent().expect("build file has parent");
        let declaration_path = if path.file_name().is_some_and(|name| name == "go.work.sum") {
            parent.join("go.work")
        } else if path.ends_with(Path::new("vendor/modules.txt")) {
            parent.parent().unwrap_or(Path::new("")).join("go.mod")
        } else {
            parent.join("go.mod")
        };
        let declaring = declarations.get(&declaration_path);
        let owner = declaring.and_then(|file| file.owner.clone());
        if path.ends_with(Path::new("vendor/modules.txt")) {
            let document = parse_vendor_modules(snapshot.source, &parser_limits, cancelled);
            let owner = if document.workspace.is_some() {
                declarations
                    .get(&parent.parent().unwrap_or(Path::new("")).join("go.work"))
                    .and_then(|file| file.owner.clone())
            } else {
                owner
            };
            let validated = document.complete()
                && !document.modules.is_empty()
                && document.workspace.is_none()
                && declaring.is_some_and(|file| module_vendor_consistent(file, path, &document));
            for error in document.issues {
                syntax_gap(&mut result, path, error.kind, error.range);
            }
            for module in document.modules {
                let source = module.replacement.as_ref().map_or_else(
                    || Some(format!("module:{}", module.module.value)),
                    |replacement| {
                        Some(format!(
                            "{}:{}",
                            if replacement.local { "local" } else { "module" },
                            replacement.source.value
                        ))
                    },
                );
                let package = module
                    .replacement
                    .as_ref()
                    .filter(|replacement| !replacement.local)
                    .map_or_else(
                        || module.module.value.clone(),
                        |replacement| replacement.source.value.clone(),
                    );
                let version = module.replacement.as_ref().map_or_else(
                    || module.version.as_ref().map(|version| version.value.clone()),
                    |replacement| {
                        replacement
                            .version
                            .as_ref()
                            .map(|version| version.value.clone())
                    },
                );
                let mut conditions = vec![condition(
                    "go_evidence",
                    if validated {
                        "validated_module_vendor_snapshot"
                    } else {
                        "unvalidated_vendor_snapshot"
                    },
                )];
                if module.explicit.is_some() {
                    conditions.push(condition("go_vendor_explicit", "true"));
                }
                let mut evidence_range = module.header_range.clone();
                if let Some(explicit) = &module.explicit {
                    evidence_range.end = evidence_range.end.max(explicit.end);
                }
                if let Some(go) = &module.declared_go {
                    evidence_range.end = evidence_range.end.max(go.range.end);
                    conditions.push(condition("go_requirement", &go.value));
                }
                if module.replacement.is_some() {
                    conditions.push(condition("go_original_module", &module.module.value));
                    if let Some(version) = &module.version {
                        conditions.push(condition("go_original_version", &version.value));
                    }
                    if module.explicit.is_none() && module.packages.is_empty() {
                        conditions.push(condition("go_constraint", "replacement_only"));
                    }
                }
                let row = DependencyEvidence {
                    ecosystem: GO_MODULE_ECOSYSTEM.to_owned(),
                    package,
                    // Until reconciliation, this is a constraint/observation,
                    // not a locked selected graph or installed instance.
                    kind: if validated
                        && module.version.is_some()
                        && (module.explicit.is_some() || !module.packages.is_empty())
                    {
                        DependencyEvidenceKind::Locked
                    } else {
                        DependencyEvidenceKind::Constraint
                    },
                    version_requirement: None,
                    exact_version: version,
                    source,
                    locator: Some(format!("vendor:{}", module.header_range.start)),
                    declared_by: owner.clone(),
                    scope: DependencyScope::Unknown,
                    conditions,
                    build_file: path.to_path_buf(),
                    source_digest: digest.clone(),
                    byte_range: evidence_range,
                    complete: validated,
                };
                if !push_row(&mut result, row, limits) {
                    return result;
                }
                if !validated {
                    gap(
                        &mut result,
                        path,
                        module.header_range,
                        DependencyEvidenceGapKind::Unresolved,
                        "Vendor snapshot selection is unvalidated against module/workspace declarations",
                    );
                }
            }
        } else {
            let document = parse_go_sum(snapshot.source, &parser_limits, cancelled);
            for error in document.issues {
                syntax_gap(&mut result, path, error.kind, error.range);
            }
            for entry in document.entries {
                let row = DependencyEvidence {
                    ecosystem: GO_MODULE_ECOSYSTEM.to_owned(),
                    package: entry.module.value.clone(),
                    kind: DependencyEvidenceKind::Checksum,
                    version_requirement: None,
                    exact_version: Some(entry.version.value),
                    source: Some(format!("module:{}", entry.module.value)),
                    locator: Some(format!("checksum:{}", entry.checksum.value)),
                    declared_by: owner.clone(),
                    scope: DependencyScope::Unknown,
                    conditions: vec![condition(
                        "go_checksum_target",
                        match entry.target {
                            GoChecksumTarget::Module => "module",
                            GoChecksumTarget::Manifest => "go.mod",
                        },
                    )],
                    build_file: path.to_path_buf(),
                    source_digest: digest.clone(),
                    byte_range: entry.range,
                    complete: true,
                };
                if !push_row(&mut result, row, limits) {
                    return result;
                }
            }
        }
    }
    // Every files-only acquisition retains the selection frontier, even when
    // all supplied declarations parsed successfully. No root requirements or
    // checksum entry justify a complete empty selected dependency graph.
    if let Some(path) = paths.first() {
        gap(
            &mut result,
            path,
            0..0,
            DependencyEvidenceGapKind::Unresolved,
            "Files-only root requirements do not establish the MVS-selected graph or installed toolchain",
        );
    } else {
        gap(
            &mut result,
            Path::new("go.mod"),
            0..0,
            DependencyEvidenceGapKind::Missing,
            "No module/workspace declarations supplied; integrity observations do not establish selection",
        );
    }
    result
}

fn declaration_row(
    file: &DeclarationFile<'_>,
    entry: &GoDirectiveEntry,
) -> Option<DependencyEvidence> {
    let (package, kind, requirement, source, conditions) = match &entry.directive {
        GoDirective::Module(_) | GoDirective::Use(_) => return None,
        GoDirective::Require {
            module,
            version,
            indirect,
        } => (
            module.value.clone(),
            DependencyEvidenceKind::Declared,
            Some(version.value.clone()),
            Some(format!("module:{}", module.value)),
            vec![condition(
                "go_indirect",
                if indirect.is_some() { "true" } else { "false" },
            )],
        ),
        GoDirective::Exclude { module, version } => (
            module.value.clone(),
            DependencyEvidenceKind::Constraint,
            Some(version.value.clone()),
            Some(format!("module:{}", module.value)),
            vec![condition("go_constraint", "excluded")],
        ),
        GoDirective::Replace {
            module,
            version,
            source,
            source_version,
            local,
        } => {
            let mut conditions = vec![
                condition("go_constraint", "replacement"),
                condition("go_original_module", &module.value),
            ];
            if let Some(version) = version {
                conditions.push(condition("go_original_version", &version.value));
            }
            (
                if *local {
                    module.value.clone()
                } else {
                    source.value.clone()
                },
                DependencyEvidenceKind::Constraint,
                source_version.as_ref().map(|version| version.value.clone()),
                Some(format!(
                    "{}:{}",
                    if *local { "local" } else { "module" },
                    source.value
                )),
                conditions,
            )
        }
        GoDirective::Go(version) => (
            "go".to_owned(),
            DependencyEvidenceKind::Constraint,
            Some(version.value.clone()),
            None,
            vec![condition("go_constraint", "declared_language_requirement")],
        ),
        GoDirective::Toolchain(version) => (
            "go".to_owned(),
            DependencyEvidenceKind::Constraint,
            Some(version.value.clone()),
            None,
            vec![condition("go_constraint", "declared_toolchain_requirement")],
        ),
    };
    Some(DependencyEvidence {
        ecosystem: if package == "go" && source.is_none() {
            GO_TOOLCHAIN_ECOSYSTEM
        } else {
            GO_MODULE_ECOSYSTEM
        }
        .to_owned(),
        package,
        kind,
        version_requirement: requirement,
        exact_version: None,
        source,
        locator: None,
        declared_by: file.owner.clone(),
        scope: DependencyScope::Unknown,
        conditions,
        build_file: file.snapshot.path.to_path_buf(),
        source_digest: file.digest.clone(),
        byte_range: entry.range.clone(),
        complete: file.document.complete() && file.owner.is_some(),
    })
}

fn condition(kind: &str, value: &str) -> DependencyCondition {
    DependencyCondition {
        kind: kind.to_owned(),
        value: value.to_owned(),
    }
}

fn gap(
    result: &mut DependencyFileEvidence,
    path: &Path,
    range: Range<usize>,
    kind: DependencyEvidenceGapKind,
    message: &str,
) {
    result.gaps.push(DependencyEvidenceGap {
        kind,
        build_file: path.to_path_buf(),
        byte_range: range,
        message: message.to_owned(),
    });
}

fn syntax_gap(
    result: &mut DependencyFileEvidence,
    path: &Path,
    kind: BuildFileIssueKind,
    range: Range<usize>,
) {
    let kind = match kind {
        BuildFileIssueKind::Malformed => DependencyEvidenceGapKind::Malformed,
        BuildFileIssueKind::Unsupported => DependencyEvidenceGapKind::Unsupported,
        BuildFileIssueKind::Duplicate | BuildFileIssueKind::Conflict => {
            DependencyEvidenceGapKind::Conflict
        }
        BuildFileIssueKind::ByteLimit
        | BuildFileIssueKind::TokenLimit
        | BuildFileIssueKind::EntryLimit => DependencyEvidenceGapKind::Limit,
        BuildFileIssueKind::Cancelled => DependencyEvidenceGapKind::Cancelled,
    };
    gap(
        result,
        path,
        range,
        kind,
        "Go build-file syntax could not be interpreted completely",
    );
}

fn push_row(
    result: &mut DependencyFileEvidence,
    row: DependencyEvidence,
    limits: &DependencyFileEvidenceLimits,
) -> bool {
    if result.rows.len() >= limits.max_rows {
        gap(
            result,
            &row.build_file,
            row.byte_range.clone(),
            DependencyEvidenceGapKind::Limit,
            "Go dependency evidence row limit",
        );
        false
    } else {
        result.rows.push(row);
        true
    }
}

fn relative_reference(build_file: &Path, reference: &str) -> Option<PathBuf> {
    if has_portable_windows_path_prefix(reference) || Path::new(reference).is_absolute() {
        return None;
    }
    let mut resolved = build_file.parent()?.to_path_buf();
    for component in Path::new(reference).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !resolved.pop() {
                    return None;
                }
            }
            Component::Normal(component) => {
                if has_portable_windows_path_prefix(component.to_str()?) {
                    return None;
                }
                resolved.push(component);
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(resolved)
}

fn apply_requirement_context(
    row: &mut DependencyEvidence,
    file: &DeclarationFile<'_>,
    declarations: &HashMap<PathBuf, DeclarationFile<'_>>,
) {
    if row.kind != DependencyEvidenceKind::Declared {
        return;
    }
    let mut workspaces: Vec<_> = declarations.values().filter(|workspace| {
        workspace.snapshot.path.file_name().is_some_and(|name| name == "go.work")
            && workspace.document.entries.iter().any(|entry| matches!(&entry.directive, GoDirective::Use(member)
                if relative_reference(workspace.snapshot.path, &member.value).is_some_and(|root| root.join("go.mod") == file.snapshot.path)))
    }).collect();
    workspaces.sort_by_key(|workspace| workspace.snapshot.path);
    if workspaces.len() > 1 {
        row.source = None;
        row.complete = false;
        row.conditions
            .push(condition("go_workspace_selection", "ambiguous"));
        return;
    }
    if let Some(workspace) = workspaces.first() {
        row.conditions.push(condition(
            "go_workspace",
            &workspace.snapshot.path.to_string_lossy().replace('\\', "/"),
        ));
    }
    let replacement = workspaces
        .first()
        .and_then(|workspace| {
            select_replacement(workspace, &row.package, row.version_requirement.as_deref())
        })
        .or_else(|| select_replacement(file, &row.package, row.version_requirement.as_deref()));
    if let Some(replacement) = replacement {
        let GoDirective::Replace {
            source,
            source_version,
            local,
            ..
        } = &replacement.directive
        else {
            unreachable!();
        };
        // Original declaration coordinates stay intact, but cannot serve as
        // applicable artifact/version evidence for the redirected source.
        row.source = None;
        row.complete = false;
        row.conditions
            .push(condition("go_source_status", "replaced"));
        row.conditions.push(condition(
            "go_replacement_source",
            &format!(
                "{}:{}",
                if *local { "local" } else { "module" },
                source.value
            ),
        ));
        if let Some(version) = source_version {
            row.conditions
                .push(condition("go_replacement_version", &version.value));
        }
    }
    if file.document.entries.iter().any(|entry| {
        matches!(&entry.directive,
        GoDirective::Exclude { module, version }
        if module.value == row.package && Some(&version.value) == row.version_requirement.as_ref())
    }) {
        row.source = None;
        row.complete = false;
        row.conditions
            .push(condition("go_source_status", "excluded"));
    }
}

/// Deliberately narrow validation: one module, exact explicit requirements and
/// replacement source equality, no workspace vendoring or inferred MVS graph.
/// A mismatch retains the vendor observation and selection frontier.
fn module_vendor_consistent(
    file: &DeclarationFile<'_>,
    vendor_path: &Path,
    vendor: &brokk_bifrost_go::build_files::GoVendorDocument,
) -> bool {
    if !file.document.complete() || file.owner.is_none() {
        return false;
    }
    if !file.document.entries.iter().any(|entry| matches!(&entry.directive, GoDirective::Go(version)
        if version.value.strip_prefix("1.").and_then(|value| value.split('.').next()).and_then(|value| value.parse::<u64>().ok()).is_some_and(|minor| minor >= 14)))
    { return false; }
    let required: HashMap<_, _> = file
        .document
        .entries
        .iter()
        .filter_map(|entry| match &entry.directive {
            GoDirective::Require {
                module, version, ..
            } => Some((module.value.as_str(), version.value.as_str())),
            _ => None,
        })
        .collect();
    if required.iter().any(|(name, version)| {
        !vendor.modules.iter().any(|module| {
            module.module.value == *name
                && module
                    .version
                    .as_ref()
                    .is_some_and(|selected| selected.value == *version)
                && module.explicit.is_some()
        })
    }) {
        return false;
    }
    for module in &vendor.modules {
        if module.explicit.is_some()
            && required.get(module.module.value.as_str()).copied()
                != module
                    .version
                    .as_ref()
                    .map(|version| version.value.as_str())
        {
            return false;
        }
        if file.document.entries.iter().any(|entry| matches!(&entry.directive,
            GoDirective::Exclude { module: excluded, version }
            if excluded.value == module.module.value && module.version.as_ref().is_some_and(|selected| selected.value == version.value)))
        { return false; }
        let expected = file.document.entries.iter().filter(|entry| matches!(&entry.directive,
            GoDirective::Replace { module: replaced, version, .. }
            if replaced.value == module.module.value && version.as_ref().is_none_or(|version| module.version.as_ref().is_some_and(|selected| selected.value == version.value))))
            .max_by_key(|entry| matches!(&entry.directive, GoDirective::Replace { version: Some(_), .. }));
        match (expected.map(|entry| &entry.directive), &module.replacement) {
            (None, None) => {}
            (
                Some(GoDirective::Replace {
                    source,
                    source_version,
                    local,
                    ..
                }),
                Some(actual),
            ) => {
                if *local != actual.local
                    || source_version.as_ref().map(|version| &version.value)
                        != actual.version.as_ref().map(|version| &version.value)
                {
                    return false;
                }
                if *local {
                    let root = vendor_path
                        .parent()
                        .and_then(Path::parent)
                        .expect("vendor path");
                    let synthetic = root.join("go.mod");
                    // Vendor replacement paths are relative to the module
                    // root, not to the vendor/modules.txt directory.
                    let expected = relative_reference(file.snapshot.path, &source.value);
                    let actual = relative_reference(&synthetic, &actual.source.value);
                    if expected.is_none() || expected != actual {
                        return false;
                    }
                } else if source.value != actual.source.value {
                    return false;
                }
            }
            _ => return false,
        }
    }
    // Every declared replacement must have its own replacement-only or
    // versioned vendor header. Otherwise a stale snapshot cannot validate.
    file.document
        .entries
        .iter()
        .filter_map(|entry| match &entry.directive {
            GoDirective::Replace { module, .. } => Some(module.value.as_str()),
            _ => None,
        })
        .all(|name| {
            vendor
                .modules
                .iter()
                .any(|module| module.module.value == name && module.replacement.is_some())
        })
}

fn select_replacement<'a>(
    file: &'a DeclarationFile<'_>,
    package: &str,
    version: Option<&str>,
) -> Option<&'a GoDirectiveEntry> {
    file.document.entries.iter().filter(|entry| matches!(&entry.directive,
        GoDirective::Replace { module, version: original_version, .. }
        if module.value == package && original_version.as_ref().is_none_or(|original| Some(original.value.as_str()) == version)))
        .max_by_key(|entry| matches!(&entry.directive, GoDirective::Replace { version: Some(_), .. }))
}

/// Module dependency rows: `require`, `replace`, `exclude`, `go.sum` and
/// `vendor/modules.txt` entries.
pub const GO_MODULE_ECOSYSTEM: &str = "go-module";
/// Toolchain rows: the `go` and `toolchain` directives of go.mod and go.work.
pub const GO_TOOLCHAIN_ECOSYSTEM: &str = "go-toolchain";

/// A version in one Go ecosystem's own ordering. A range only ever compares
/// versions of the ecosystem it was parsed for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoVersion {
    /// Semantic version precedence; build metadata (`+incompatible`) is
    /// ignored and pseudo-versions order as the prereleases they are.
    Module(semver::Version),
    Toolchain(GoToolchainVersion),
}

/// A Go release version in `go/version` order: `1.21` (the language
/// version) < `1.21rc1` < `1.21.0` < `1.21.1`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GoToolchainVersion {
    major: u64,
    minor: Option<u64>,
    patch: Option<u64>,
    prerelease: Option<(GoPrereleaseKind, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum GoPrereleaseKind {
    Alpha,
    Beta,
    Rc,
}

impl GoVersion {
    pub fn parse(ecosystem: &str, text: &str) -> Result<Self, String> {
        match ecosystem {
            GO_MODULE_ECOSYSTEM => semver::Version::parse(text.strip_prefix('v').unwrap_or(text))
                .map(Self::Module)
                .map_err(|error| format!("{text:?} is not a Go module version: {error}")),
            GO_TOOLCHAIN_ECOSYSTEM => GoToolchainVersion::parse(text).map(Self::Toolchain),
            _ => unreachable!("{ecosystem} is not a Go version ecosystem"),
        }
    }
}

impl GoToolchainVersion {
    /// Accepts the `go1.21.0` spelling of a toolchain name as well.
    pub fn parse(text: &str) -> Result<Self, String> {
        let invalid = || format!("{text:?} is not a Go release version");
        let number = |part: &str| {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid());
            }
            part.parse::<u64>().map_err(|_| invalid())
        };
        let version = text.strip_prefix("go").unwrap_or(text);
        let mut parts = version.split('.');
        let major = number(parts.next().expect("split yields one part"))?;
        let Some(minor) = parts.next() else {
            return Ok(Self {
                major,
                minor: None,
                patch: None,
                prerelease: None,
            });
        };
        let patch = parts.next().map(number).transpose()?;
        if parts.next().is_some() {
            return Err(invalid());
        }
        let prerelease = [
            ("alpha", GoPrereleaseKind::Alpha),
            ("beta", GoPrereleaseKind::Beta),
            ("rc", GoPrereleaseKind::Rc),
        ]
        .into_iter()
        .find_map(|(label, kind)| {
            minor
                .split_once(label)
                .map(|(minor, number)| (minor, kind, number))
        });
        let (minor, prerelease) = match prerelease {
            // Go publishes prereleases only before the first patch release.
            Some(_) if patch.is_some() => return Err(invalid()),
            Some((minor, kind, ordinal)) => (minor, Some((kind, number(ordinal)?))),
            None => (minor, None),
        };
        Ok(Self {
            major,
            minor: Some(number(minor)?),
            patch,
            prerelease,
        })
    }
}

impl Ord for GoVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::Module(left), Self::Module(right)) => left.cmp_precedence(right),
            (Self::Toolchain(left), Self::Toolchain(right)) => left.cmp(right),
            _ => unreachable!("Go versions of different ecosystems are never compared"),
        }
    }
}

impl PartialOrd for GoVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// An authored affected-version range for one Go ecosystem: `||`-joined
/// alternatives of whitespace-joined comparators (`>=1.24.0 <1.24.4`).
/// Semver's VersionReq is deliberately not used: its implicit prerelease
/// exclusion would lose Go pseudo-versions inside an affected range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoVersionRange {
    ecosystem: &'static str,
    alternatives: Vec<Vec<(VersionComparator, GoVersion)>>,
}

impl GoVersionRange {
    pub fn parse(ecosystem: &str, text: &str) -> Result<Self, String> {
        let ecosystem = match ecosystem {
            GO_MODULE_ECOSYSTEM => GO_MODULE_ECOSYSTEM,
            GO_TOOLCHAIN_ECOSYSTEM => GO_TOOLCHAIN_ECOSYSTEM,
            _ => unreachable!("{ecosystem} is not a Go version ecosystem"),
        };
        let alternatives = text
            .split("||")
            .map(|alternative| {
                let bounds = parse_version_comparators(alternative, |version| {
                    GoVersion::parse(ecosystem, version)
                })?;
                if bounds.is_empty() {
                    return Err("an empty Go version range alternative".to_owned());
                }
                Ok(bounds)
            })
            .collect::<Result<_, String>>()?;
        Ok(Self {
            ecosystem,
            alternatives,
        })
    }
}

/// Whether one complete locked or installed row of the range's ecosystem has
/// an exact version in `range`. Declared minimums (`go`, `toolchain`,
/// `require`), constraints, checksums, replaced or excluded sources and
/// unvalidated vendor snapshots have no exact selected version and stay
/// unknown, so a minimum is never mistaken for the toolchain that builds.
pub fn go_dependency_version_matches(
    row: &DependencyEvidence,
    range: &GoVersionRange,
) -> Result<Option<bool>, String> {
    if row.ecosystem != range.ecosystem
        || !row.complete
        || !matches!(
            row.kind,
            DependencyEvidenceKind::Locked | DependencyEvidenceKind::Installed
        )
        || (row.ecosystem == GO_MODULE_ECOSYSTEM
            && row
                .source
                .as_deref()
                .and_then(|source| source.strip_prefix("module:"))
                != Some(row.package.as_str()))
    {
        return Ok(None);
    }
    row.exact_version
        .as_deref()
        .map(|version| {
            GoVersion::parse(range.ecosystem, version)
                .map(|version| version_bounds_admit(&range.alternatives, &version))
        })
        .transpose()
}

#[cfg(test)]
mod tests {

    use crate::analyzer::go::build_evidence::*;

    fn acquire(inputs: &[(&str, &str)]) -> DependencyFileEvidence {
        let snapshots: Vec<_> = inputs
            .iter()
            .map(|(path, source)| GoBuildSnapshot {
                path: Path::new(path),
                source,
                oid: git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap(),
            })
            .collect();
        collect_go_build_evidence(&snapshots, &DependencyFileEvidenceLimits::default(), None)
    }

    #[test]
    fn workspace_declarations_have_distinct_owners_and_checksums_do_not_select() {
        let result = acquire(&[
            (
                "go.work",
                "go 1.26\nuse (\n ./affected\n ./fixed\n ./missing\n)\n",
            ),
            (
                "affected/go.mod",
                "module example.com/affected\ngo 1.26\nrequire example.com/lib v1.2.0\nreplace example.com/local => ../local\n",
            ),
            (
                "fixed/go.mod",
                "module example.com/fixed\ngo 1.26\nrequire example.com/lib v1.3.0\n",
            ),
            (
                "affected/go.sum",
                "example.com/lib v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
            ),
        ]);
        let requirements: Vec<_> = result
            .rows
            .iter()
            .filter(|row| row.kind == DependencyEvidenceKind::Declared)
            .collect();
        assert_eq!(requirements.len(), 2);
        assert_eq!(
            requirements[0].version_requirement.as_deref(),
            Some("v1.2.0")
        );
        assert_eq!(
            requirements[1].version_requirement.as_deref(),
            Some("v1.3.0")
        );
        assert_ne!(requirements[0].declared_by, requirements[1].declared_by);
        assert!(requirements.iter().all(|row| row.exact_version.is_none()));
        let checksum = result
            .rows
            .iter()
            .find(|row| row.kind == DependencyEvidenceKind::Checksum)
            .unwrap();
        assert_eq!(checksum.exact_version.as_deref(), Some("v1.0.0"));
        assert_eq!(checksum.declared_by, requirements[0].declared_by);
        assert!(
            result
                .gaps
                .iter()
                .any(|gap| gap.kind == DependencyEvidenceGapKind::Missing)
        );
        assert!(
            result
                .gaps
                .iter()
                .any(|gap| gap.kind == DependencyEvidenceGapKind::Unresolved)
        );
        assert!(!result.complete());
    }

    #[test]
    fn replacements_and_exclusions_never_publish_original_artifact_applicability() {
        let result = acquire(&[
            (
                "go.work",
                "go 1.26\nuse ./app\nreplace example.com/lib => example.com/fork/v2 v2.0.0\n",
            ),
            (
                "app/go.mod",
                "module example.com/app\ngo 1.26\nrequire example.com/lib v1.2.0\nrequire example.com/other v1.0.0\nexclude example.com/other v1.0.0\n",
            ),
        ]);
        let requirements: Vec<_> = result
            .rows
            .iter()
            .filter(|row| row.kind == DependencyEvidenceKind::Declared)
            .collect();
        assert_eq!(requirements.len(), 2);
        assert!(
            requirements
                .iter()
                .all(|row| row.source.is_none() && !row.complete)
        );
        let replacement = result
            .rows
            .iter()
            .find(|row| row.package == "example.com/fork/v2")
            .unwrap();
        assert_eq!(
            replacement.source.as_deref(),
            Some("module:example.com/fork/v2")
        );
        assert_eq!(replacement.version_requirement.as_deref(), Some("v2.0.0"));
        assert!(replacement.exact_version.is_none());
    }

    #[test]
    fn only_consistent_module_vendor_snapshots_publish_locked_rows() {
        let manifest = "module example.com/app\ngo 1.26\nrequire example.com/lib v1.2.0\n";
        let consistent = "# example.com/lib v1.2.0\n## explicit; go 1.26\nexample.com/lib/sub\n";
        let result = acquire(&[("go.mod", manifest), ("vendor/modules.txt", consistent)]);
        let locked = result
            .rows
            .iter()
            .find(|row| row.kind == DependencyEvidenceKind::Locked)
            .unwrap();
        assert_eq!(locked.exact_version.as_deref(), Some("v1.2.0"));
        assert!(locked.complete);
        let stale = acquire(&[
            ("go.mod", manifest),
            (
                "vendor/modules.txt",
                "# example.com/lib v1.1.0\n## explicit\n",
            ),
        ]);
        assert!(
            stale
                .rows
                .iter()
                .all(|row| row.kind != DependencyEvidenceKind::Locked)
        );
        assert!(!stale.complete());
    }
}
