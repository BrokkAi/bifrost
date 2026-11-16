//! Position-free certificates for Go's generation authorities.
use super::GoAnalyzer;
use brokk_bifrost_analysis::analyzer::semantic::StableDigest;
use brokk_bifrost_analysis::analyzer::workspace_authority::AuthorityInputs;
use brokk_bifrost_analysis::analyzer::{FactSubject, IAnalyzer, Language, WorkspaceFactFamily};

// Encode the exact stable reasons captured by the cache fill. Refused sources
// that only explain an exclusion do not appear here unless a read recorded a
// gap. The receipt rejects operational reasons, so they cannot be retained.
pub(super) fn stable_completion(
    analyzer: &dyn IAnalyzer,
    reasons: Vec<brokk_bifrost_analysis::analyzer::QueryReadIncomplete>,
) -> Vec<brokk_bifrost_go::packages::GoReadGap> {
    use brokk_bifrost_analysis::analyzer::QueryReadIncomplete;
    use brokk_bifrost_go::packages::{GoReadGap, GoReadGapKind};
    let mut completion = reasons
        .into_iter()
        .filter_map(|reason| {
            if matches!(reason, QueryReadIncomplete::Attributed(_)) {
                // Both callers run inside the cache fill's nested read captures,
                // before receipt admission and authority publication. Refuse reuse
                // while keeping the typed reason in the failed-wave receipt.
                // Only the base stable gap belongs in this position-free projection.
                analyzer.refuse_read_reuse();
            }
            match reason.base_cause() {
                QueryReadIncomplete::StructureUnavailable(file) => Some(GoReadGap {
                    kind: GoReadGapKind::StructureUnavailable,
                    detail: brokk_bifrost_core::path_utils::rel_path_string(file),
                }),
                QueryReadIncomplete::ArtifactUnavailable(detail) => Some(GoReadGap {
                    kind: GoReadGapKind::ArtifactUnavailable,
                    detail: detail.to_string(),
                }),
                QueryReadIncomplete::SemanticEvidenceGap(detail) => Some(GoReadGap {
                    kind: GoReadGapKind::SemanticEvidenceGap,
                    detail: detail.to_string(),
                }),
                // Execution-dependent reasons make the fill refuse, so a retained
                // value never carries one. Listing them keeps a new variant from
                // silently escaping the certificate.
                QueryReadIncomplete::ProofStopped {
                    reason,
                    cause: None,
                } => Some(GoReadGap {
                    kind: GoReadGapKind::SemanticEvidenceGap,
                    detail: (*reason).into(),
                }),
                QueryReadIncomplete::ProofStopped { cause: Some(_), .. } => None,
                QueryReadIncomplete::SemanticModelsPending
                | QueryReadIncomplete::Cancelled
                | QueryReadIncomplete::SemanticEvidenceUnavailable(_)
                | QueryReadIncomplete::StoreFailure(_) => None,
                QueryReadIncomplete::Attributed(_) => {
                    unreachable!("base cause cannot be attributed")
                }
            }
        })
        .collect::<Vec<_>>();
    completion.sort();
    completion.dedup();
    completion
}

pub(super) fn profile_answer(value: Option<[u8; 32]>) -> StableDigest {
    let mut hash =
        brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(b"go-build-profile-v1");
    hash.value(&[u8::from(value.is_some())]);
    if let Some(value) = value {
        hash.value(&value);
    }
    StableDigest::from_array(hash.finish())
}

// Failure text can contain checkout paths and source positions. It cannot
// certify a reusable answer; only the successful, empty state gets a fact.
pub(super) fn selection_error_answer(error: &str) -> Option<StableDigest> {
    error
        .is_empty()
        .then(|| StableDigest::sha256(b"go-build-selection-ready-v1"))
}

pub(super) fn selection_input(name: &str, answer: StableDigest) -> AuthorityInputs<'static> {
    AuthorityInputs::Fact {
        language: Language::Go,
        subject: FactSubject::Named { name: name.into() },
        answer,
    }
}

// This memo lives in the inner analyzer's request registry, never on GoAnalyzer.
// The authority wrapper records the certificate on hits as well as fills.
type MembershipKey = ([u8; 32], String, String);
pub(super) struct GoMembershipMemo {
    answers: brokk_bifrost_analysis::analyzer::workspace_authority::WorkspaceAuthorityMemo<
        std::sync::Mutex<std::collections::HashMap<MembershipKey, Option<DomainEvidence>>>,
    >,
    pub(super) scans: std::sync::atomic::AtomicUsize,
}
impl Default for GoMembershipMemo {
    fn default() -> Self {
        Self {
            answers:
                brokk_bifrost_analysis::analyzer::workspace_authority::WorkspaceAuthorityMemo::new(
                    WorkspaceFactFamily::GoBuildSelection,
                    Default::default(),
                ),
            scans: Default::default(),
        }
    }
}

/// What recording one domain's membership needs: the membership answer, and the
/// environment part of that answer, if the domain has one.
#[derive(Clone)]
struct DomainEvidence {
    answer: StableDigest,
    /// The provider reads that go with the answer. Empty when the domain has no
    /// module or standard-library package.
    providers: Vec<ProviderRead>,
}

/// How a domain's module and standard-library packages are recorded (#11607).
#[derive(Clone)]
enum ProviderRead {
    /// Every row is determined by the tree and the profile, except for what `go
    /// list` read outside the checkout: `names` are those directories or module
    /// roots, and `member` says which of the two reads this is. Replay reads
    /// the same ones in the head's environment.
    State {
        member: &'static str,
        names: Vec<Box<str>>,
        answer: StableDigest,
    },
    /// A row reports something the environment decided, or a provider directory
    /// cannot be read. The membership then replays only when the head is the
    /// base tree.
    Unverifiable,
}

/// The module package directories `go list` read, see
/// [`provider_module_trees_answer`].
const PROVIDER_STATE_MEMBER: &str = "providers";
/// The standard-library package directories, see [`provider_standard_directories_answer`].
const PROVIDER_STANDARD_MEMBER: &str = "provider_standard";
/// The module roots of those packages and the local replacement directories
/// outside the checkout that the domain's go.mod names, see [`provider_roots_answer`].
const PROVIDER_ROOTS_MEMBER: &str = "provider_roots";
const UNVERIFIABLE_PROVIDERS: &str = "provider_state_unverified";

/// Computes the answer for one provider member from its names.
type ProviderAnswer = fn(&[Box<str>]) -> Option<StableDigest>;

impl ProviderRead {
    fn inputs(&self) -> AuthorityInputs<'static> {
        match self {
            Self::State {
                member,
                names,
                answer,
            } => AuthorityInputs::Fact {
                language: Language::Go,
                subject: FactSubject::name_group_member(names.clone(), (*member).into()),
                answer: *answer,
            },
            Self::Unverifiable => unverifiable_providers_input(),
        }
    }
}

fn unverifiable_providers_input() -> AuthorityInputs<'static> {
    selection_input(UNVERIFIABLE_PROVIDERS, unverifiable_providers_answer())
}

// A constant: the read exists so that no export-based replay admits the
// evaluation. A head that is the base tree is checked by the membership read.
fn unverifiable_providers_answer() -> StableDigest {
    StableDigest::sha256(b"go-provider-state-unverified-v1")
}

/// The state of the module package directories `go list` read outside the
/// checkout (external modules and local replacements): everything an edit could
/// change in what the tool reports for them. Per package directory that is its
/// whole subtree, because a `//go:embed` pattern can name files in
/// subdirectories (`//go:embed assets/*`), and the tool reports a missing or
/// empty match as a package error, which decides the package's completeness. The
/// recorded discovery rows do not keep the patterns or the matched files, so
/// nothing narrower than the subtree is known to be sufficient.
///
/// Each file is read once even when package directories overlap (a parent
/// package directory and its subpackage directories), in sorted path order.
/// Per file:
///
/// - a regular file contributes its name and its full bytes, so the Go files
///   (package name, imports, errors), the C, assembly and header files (build
///   constraints) and the embed targets are all covered;
/// - a test file (`*_test.go`) contributes name and length only, because it is
///   not part of what the tool lists for a dependency;
/// - a symlink contributes its target text without following it, plus the
///   bytes of the file it names when that is a regular file, because the tool
///   reads symlinked Go files and, with `embedfollowsymlinks`, embeds them.
///
/// The walk does not enter a subdirectory that holds its own `go.mod`: that is a
/// different module, and the tool refuses an embed pattern that crosses into
/// it. Only the subdirectory's name is recorded, so adding or removing the
/// boundary changes the answer. Every directory the walk enters is recorded
/// by path too, so adding an empty directory changes the answer: an embed
/// pattern that matches it makes the tool report that it contains no
/// embeddable files. It does not enter `.git`, `.hg`, `.bzr` and `.svn`, which
/// the tool refuses to embed from. A module cache directory never
/// changes once extracted, so a change here is a modified cache or an edited
/// local replacement. `None` when an entry cannot be read. The module metadata
/// that lies outside the package directories is [`provider_roots_answer`].
pub(super) fn provider_module_trees_answer(directories: &[Box<str>]) -> Option<StableDigest> {
    use std::path::PathBuf;
    let mut hash =
        brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(b"go-provider-state-v4");
    let mut files: Vec<PathBuf> = Vec::new();
    let mut boundaries: Vec<PathBuf> = Vec::new();
    let mut visited: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for directory in directories {
        hash.value(directory.as_bytes());
        let mut stack = vec![PathBuf::from(&**directory)];
        while let Some(current) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            for entry in std::fs::read_dir(&current).ok()? {
                let entry = entry.ok()?;
                let path = entry.path();
                let file_type = entry.file_type().ok()?;
                if !file_type.is_dir() {
                    // Regular files and symlinks. Sockets and devices cannot be
                    // embedded or compiled.
                    if file_type.is_file() || file_type.is_symlink() {
                        files.push(path);
                    }
                    continue;
                }
                if matches!(
                    entry.file_name().as_encoded_bytes(),
                    b".git" | b".hg" | b".bzr" | b".svn"
                ) {
                    continue;
                }
                match std::fs::metadata(path.join("go.mod")) {
                    Ok(_) => boundaries.push(path),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => stack.push(path),
                    Err(_) => return None,
                }
            }
        }
    }
    files.sort();
    files.dedup();
    boundaries.sort();
    boundaries.dedup();
    let mut entered: Vec<PathBuf> = visited.into_iter().collect();
    entered.sort();
    hash.value(b"directories");
    for directory in &entered {
        hash.value(directory.as_os_str().as_encoded_bytes());
    }
    hash.value(b"module-boundaries");
    for boundary in &boundaries {
        hash.value(boundary.as_os_str().as_encoded_bytes());
    }
    hash.value(b"files");
    for path in &files {
        hash.value(path.as_os_str().as_encoded_bytes());
        if std::fs::symlink_metadata(path).ok()?.is_symlink() {
            hash.value(&[1]);
            hash.value(
                std::fs::read_link(path)
                    .ok()?
                    .as_os_str()
                    .as_encoded_bytes(),
            );
        } else {
            hash.value(&[0]);
        }
        // Metadata follows symlinks: a linked file is the file it names. A
        // broken link or a link to a directory has no content to read.
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => {
                hash.value(&[1]);
                hash.value(&metadata.len().to_le_bytes());
                if !path.as_os_str().as_encoded_bytes().ends_with(b"_test.go") {
                    hash.value(&std::fs::read(path).ok()?);
                }
            }
            Ok(_) => hash.value(&[0]),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => hash.value(&[0]),
            Err(_) => return None,
        }
    }
    Some(StableDigest::from_array(hash.finish()))
}

/// The state of the standard-library package directories `go list` read: for
/// each directory, its regular files' names and lengths, and the full bytes of
/// every regular file that is not a test file. Only the files directly in the
/// directory are read, not its subtree, unlike [`provider_module_trees_answer`]:
/// the standard library's contents are pinned by the toolchain identity the
/// profile already covers (GOROOT and GOVERSION from `go env`), so a change here
/// is a different toolchain or a modified installation, and the standard
/// library's embed targets are not a way for an edit to go unnoticed. `None`
/// when a directory or a file in it cannot be read.
pub(super) fn provider_standard_directories_answer(
    directories: &[Box<str>],
) -> Option<StableDigest> {
    let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
        b"go-provider-standard-v1",
    );
    for directory in directories {
        let mut files = std::fs::read_dir(&**directory)
            .ok()?
            .map(|entry| {
                let entry = entry.ok()?;
                // Metadata follows symlinks: a linked file is the file it names.
                let metadata = std::fs::metadata(entry.path()).ok()?;
                Some((entry.file_name(), entry.path(), metadata))
            })
            .collect::<Option<Vec<_>>>()?;
        files.sort_by(|left, right| left.0.cmp(&right.0));
        hash.value(directory.as_bytes());
        for (name, path, metadata) in files.iter().filter(|file| file.2.is_file()) {
            let name = name.as_encoded_bytes();
            hash.value(name);
            hash.value(&metadata.len().to_le_bytes());
            if !name.ends_with(b"_test.go") {
                hash.value(&std::fs::read(path).ok()?);
            }
        }
    }
    Some(StableDigest::from_array(hash.finish()))
}

/// The module metadata `go list` read for each recorded module root (the root of
/// a replacement module, of a module cache entry, or `GOROOT/src`): the full
/// bytes of `go.mod`, which decides the required Go version, the requirements
/// and the replacements the tool applies to the module's packages, and of
/// `go.sum` when present, which the tool checks module content against. The
/// root lies outside every package directory when only a subpackage is
/// imported, so [`provider_module_trees_answer`] does not see it. The roots also
/// include the local `replace` targets outside the checkout, even when no
/// package is imported from them: the tool reads their
/// `go.mod` to select module versions, and the tree does not pin them. `None`
/// when a root has no readable `go.mod`, or a `go.sum` that exists cannot be
/// read.
pub(super) fn provider_roots_answer(roots: &[Box<str>]) -> Option<StableDigest> {
    let mut hash =
        brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(b"go-provider-roots-v2");
    for root in roots {
        let root_path = std::path::Path::new(&**root);
        hash.value(root.as_bytes());
        hash.value(&std::fs::read(root_path.join("go.mod")).ok()?);
        match std::fs::read(root_path.join("go.sum")) {
            Ok(sum) => {
                hash.value(&[1]);
                hash.value(&sum);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => hash.value(&[0]),
            Err(_) => return None,
        }
    }
    Some(StableDigest::from_array(hash.finish()))
}

/// One domain's discovery rows, read from the store.
fn domain_membership_rows(
    go: &GoAnalyzer,
    snapshot: &brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId,
    base: &[u8; 32],
    directory: &str,
    work: &str,
) -> Option<brokk_bifrost_analysis::analyzer::store::go_package_context::GoDomainMembershipRows> {
    let rows = match go
        .inner
        .analyzer_store()
        .go_domain_membership_rows(snapshot, base, directory, work)
    {
        Ok(rows) => rows,
        Err(error) => {
            go.inner.record_store_error(error);
            return None;
        }
    };
    brokk_bifrost_core::profiling::note_with(|| {
        format!("go.membership_scan domain={directory:?} gowork={work:?} rows={rows:?}")
    });
    Some(rows)
}

fn membership_digest(
    rows: &brokk_bifrost_analysis::analyzer::store::go_package_context::GoDomainMembershipRows,
) -> StableDigest {
    // The answer covers every discovery output analysis reads for the domain's
    // selected publications, not only package and file names: a package that keeps
    // its names but loses completeness, gains a gap, changes provider or module
    // version, or retargets an import must not replay an old complete result.
    let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
        b"go-domain-membership-v2",
    );
    for (section, rows) in [
        (&b"publication"[..], &rows.publications),
        (b"module", &rows.modules),
        (b"package", &rows.packages),
        (b"file", &rows.files),
        (b"import", &rows.imports),
    ] {
        hash.value(section);
        hash.value(&(rows.len() as u64).to_le_bytes());
        for row in rows {
            for value in row {
                hash.value(&[u8::from(value.is_some())]);
                if let Some(value) = value {
                    hash.value(value.as_bytes());
                }
            }
        }
    }
    StableDigest::from_array(hash.finish())
}

/// The single membership answer implementation, also intended for later replay.
/// Call without the request memo when checking a previously recorded answer.
pub(super) fn selected_domain_membership_answer(
    go: &GoAnalyzer,
    snapshot: &brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId,
    base: &[u8; 32],
    directory: &str,
    work: &str,
) -> Option<StableDigest> {
    domain_membership_rows(go, snapshot, base, directory, work).map(|rows| membership_digest(&rows))
}

/// The membership answer and the environment part it needs for replay. The
/// membership is a function of the tree, the profile and the module and
/// standard-library directories (#11607): rows that report an environment
/// finding, or directories that cannot be read, leave it unverifiable.
fn selected_domain_evidence(
    go: &GoAnalyzer,
    snapshot: &brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId,
    base: &[u8; 32],
    directory: &str,
    work: &str,
) -> Option<DomainEvidence> {
    let rows = domain_membership_rows(go, snapshot, base, directory, work)?;
    let modules = rows.module_provider_directories();
    let standard = rows.standard_provider_directories();
    let providers = if !rows.gaps_are_tree_determined() {
        vec![ProviderRead::Unverifiable]
    } else if !work.is_empty() {
        // `work` is the workspace-relative go.work file; empty means GOWORK=off.
        // In workspace mode cmd/go does not require go.sum entries for every
        // go.mod in the module graph (`mustHaveSums` is false) and discovery
        // sets GOSUMDB=off, so the go.mod of a module-cache module that
        // contributes no selected package is neither pinned by the tree nor
        // covered by a recorded read. Such a domain is not export-verifiable;
        // it replays only when the head is the base tree. Trusting module-cache
        // content by its go.sum hash (#11788) is where this can be relaxed.
        vec![ProviderRead::Unverifiable]
    } else {
        // Module graph loading reads the go.mod of every local replacement
        // target outside the checkout, whether or not a package was selected
        // from it: its requirements can raise the version selected for another
        // module. Those directories are roots too.
        let replaced = match go
            .inner
            .analyzer_store()
            .go_module_outside_replacement_directories(
                snapshot,
                go.inner.project().root(),
                directory,
            ) {
            Ok(replaced) => replaced,
            Err(error) => {
                go.inner.record_store_error(error);
                return None;
            }
        };
        // A root that cannot be derived from a recorded package never occurs
        // for a provider `go list` read, but nothing proves that for every
        // toolchain output, so it is a gap and never an empty set of roots.
        let roots = rows.provider_roots();
        match (roots, replaced) {
            (Some(mut roots), Ok(replaced)) => {
                roots.extend(replaced);
                roots.sort();
                roots.dedup();
                debug_assert!(
                    !roots.is_empty() || (modules.is_empty() && standard.is_empty()),
                    "every module or standard package has a root: {rows:?}"
                );
                let reads: [(&'static str, Vec<Box<str>>, ProviderAnswer); 3] = [
                    (PROVIDER_STATE_MEMBER, modules, provider_module_trees_answer),
                    (
                        PROVIDER_STANDARD_MEMBER,
                        standard,
                        provider_standard_directories_answer,
                    ),
                    (PROVIDER_ROOTS_MEMBER, roots, provider_roots_answer),
                ];
                reads
                    .into_iter()
                    .filter(|(_, names, _)| !names.is_empty())
                    .map(|(member, names, answer)| {
                        answer(&names).map(|answer| ProviderRead::State {
                            member,
                            names,
                            answer,
                        })
                    })
                    .collect::<Option<Vec<_>>>()
                    .unwrap_or_else(|| vec![ProviderRead::Unverifiable])
            }
            (roots, replaced) => {
                brokk_bifrost_core::profiling::note_with(|| {
                    format!(
                        "go.provider_state_unverified domain={directory:?} \
                         roots={roots:?} replacements={replaced:?}"
                    )
                });
                vec![ProviderRead::Unverifiable]
            }
        }
    };
    Some(DomainEvidence {
        answer: membership_digest(&rows),
        providers,
    })
}

fn domain_set_answer(domains: &[(String, String)]) -> StableDigest {
    let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
        b"go-selected-domains-v1",
    );
    for (directory, work) in domains {
        hash.value(directory.as_bytes());
        hash.value(work.as_bytes());
    }
    StableDigest::from_array(hash.finish())
}

// The selected domains, read for both recording and replay of the same answer.
fn selected_domain_keys(
    go: &GoAnalyzer,
    snapshot: &brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId,
    base: &[u8; 32],
) -> Option<Vec<(String, String)>> {
    match go
        .inner
        .analyzer_store()
        .go_selected_domain_keys(snapshot, base)
    {
        Ok(domains) => Some(domains),
        Err(error) => {
            go.inner.record_store_error(error);
            None
        }
    }
}

// One domain's membership is the question; its answer is the digest of that
// domain's selected rows. The domain is named by its directory and go.work path.
fn membership_input(
    directory: &str,
    work: &str,
    answer: &Option<StableDigest>,
) -> AuthorityInputs<'static> {
    answer.map_or(AuthorityInputs::Unnamed, |answer| AuthorityInputs::Fact {
        language: Language::Go,
        subject: FactSubject::NamedMember {
            owner: directory.into(),
            member: work.into(),
        },
        answer,
    })
}

pub(super) fn record_build_membership(go: &GoAnalyzer, base: Option<[u8; 32]>) {
    use brokk_bifrost_analysis::analyzer::workspace_authority::{
        AuthorityInputs, memo_attribution, record_workspace_authority_read,
    };
    // Membership is evidence for a recorder only. With none active, the scan
    // has no consumer, so an ordinary profile read stays cheap.
    if !memo_attribution(go).is_recording_authorities() {
        return;
    }
    let read = || {
        let base = base?;
        let snapshots = go.inner.selected_workspace_snapshots();
        let snapshot = snapshots.get("go")?;
        let domains = selected_domain_keys(go, snapshot, &base)?;
        record_workspace_authority_read(
            go,
            WorkspaceFactFamily::GoBuildSelection,
            selection_input("domains", domain_set_answer(&domains)),
        );
        let memo = go.inner.active_query_request_memo::<GoMembershipMemo>();
        for (directory, work) in domains {
            let membership = |evidence: &Option<DomainEvidence>| {
                membership_input(
                    &directory,
                    &work,
                    &evidence.as_ref().map(|evidence| evidence.answer),
                )
            };
            let providers = |evidence: &Option<DomainEvidence>, index: usize| {
                evidence
                    .as_ref()
                    .map_or(AuthorityInputs::Unnamed, |evidence| {
                        evidence.providers[index].inputs()
                    })
            };
            let provider_count = |evidence: &Option<DomainEvidence>| {
                evidence.as_ref().map_or(0, |e| e.providers.len())
            };
            if let Some(memo) = &memo {
                let key = (base, directory.clone(), work.clone());
                let read =
                    |inputs: &dyn Fn(&Option<DomainEvidence>) -> AuthorityInputs<'static>| {
                        memo.answers.read(
                            &memo_attribution(go),
                            |answers| {
                                answers
                                    .lock()
                                    .expect("Go membership memo poisoned")
                                    .entry(key.clone())
                                    .or_insert_with(|| {
                                        memo.scans
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        selected_domain_evidence(
                                            go, snapshot, &base, &directory, &work,
                                        )
                                    })
                                    .clone()
                            },
                            inputs,
                        )
                    };
                let evidence = read(&membership);
                // A memo hit records the provider read again, as it records the
                // membership read.
                for index in 0..provider_count(&evidence) {
                    read(&|evidence| providers(evidence, index));
                }
            } else {
                let evidence = selected_domain_evidence(go, snapshot, &base, &directory, &work);
                record_workspace_authority_read(
                    go,
                    WorkspaceFactFamily::GoBuildSelection,
                    membership(&evidence),
                );
                for index in 0..provider_count(&evidence) {
                    record_workspace_authority_read(
                        go,
                        WorkspaceFactFamily::GoBuildSelection,
                        providers(&evidence, index),
                    );
                }
            }
        }
        Some(())
    };
    if read().is_none() {
        record_workspace_authority_read(
            go,
            WorkspaceFactFamily::GoBuildSelection,
            AuthorityInputs::Unnamed,
        );
    }
}

pub(super) fn answer(
    analyzer: &dyn IAnalyzer,
    family: WorkspaceFactFamily,
    language: Language,
    subject: &FactSubject,
) -> Option<StableDigest> {
    if language != Language::Go {
        return None;
    }
    let go = brokk_bifrost_analysis::analyzer::resolve_analyzer::<GoAnalyzer>(analyzer)?;
    match (family, subject) {
        (WorkspaceFactFamily::GoWorkspaceIndexes, FactSubject::Named { name }) => go
            .workspace_indexes(subject.clone())
            .ok()
            .map(|indexes| StableDigest::from_array(indexes.hierarchy.read_answer(name))),
        (WorkspaceFactFamily::GoWorkspaceIndexes, FactSubject::Whole) => go
            .workspace_indexes(FactSubject::Whole)
            .ok()
            .map(|indexes| StableDigest::from_array(indexes.usage_answer)),
        (WorkspaceFactFamily::GoWorkspacePaths, FactSubject::Whole) => Some(
            StableDigest::from_array(go.workspace_path_index().read_answer()),
        ),
        (WorkspaceFactFamily::GoImportFacts, FactSubject::Whole) => Some(go.import_facts().answer),
        (WorkspaceFactFamily::GoReverseImports, FactSubject::Whole) => {
            go.reverse_import_index().answer
        }
        (WorkspaceFactFamily::GoBuildSelection, FactSubject::Named { name })
            if name.as_ref() == "profile" =>
        {
            Some(profile_answer(*go.profile_read()))
        }
        (WorkspaceFactFamily::GoBuildSelection, FactSubject::Named { name })
            if name.as_ref() == "error" =>
        {
            selection_error_answer(&go.selection_error_read())
        }
        // Membership is recomputed by the functions that recorded it.
        (WorkspaceFactFamily::GoBuildSelection, FactSubject::Named { name })
            if name.as_ref() == "domains" =>
        {
            let base = (*go.profile_read())?;
            let snapshots = go.inner.selected_workspace_snapshots();
            let domains = selected_domain_keys(go, snapshots.get("go")?, &base)?;
            Some(domain_set_answer(&domains))
        }
        // The state of the directories and module roots a recorded membership
        // read outside the checkout, read again in this analyzer's environment.
        (WorkspaceFactFamily::GoBuildSelection, FactSubject::NameGroupMember { names, member })
            if member.as_ref() == PROVIDER_STATE_MEMBER =>
        {
            provider_module_trees_answer(names)
        }
        (WorkspaceFactFamily::GoBuildSelection, FactSubject::NameGroupMember { names, member })
            if member.as_ref() == PROVIDER_STANDARD_MEMBER =>
        {
            provider_standard_directories_answer(names)
        }
        (WorkspaceFactFamily::GoBuildSelection, FactSubject::NameGroupMember { names, member })
            if member.as_ref() == PROVIDER_ROOTS_MEMBER =>
        {
            provider_roots_answer(names)
        }
        (WorkspaceFactFamily::GoBuildSelection, FactSubject::Named { name })
            if name.as_ref() == UNVERIFIABLE_PROVIDERS =>
        {
            Some(unverifiable_providers_answer())
        }
        (WorkspaceFactFamily::GoBuildSelection, FactSubject::NamedMember { owner, member }) => {
            let base = (*go.profile_read())?;
            let snapshots = go.inner.selected_workspace_snapshots();
            selected_domain_membership_answer(go, snapshots.get("go")?, &base, owner, member)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    #[cfg(target_os = "linux")]
    use crate::test_support::OTHER_TOOLCHAIN_GO_ENV_SCRIPT;
    use brokk_bifrost_analysis::analyzer::{
        LookupKind, LookupQuestion, ReadKey, capture_query_reads,
    };
    use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#10984: attributed Go completion must refuse reuse without omitting its base gap")]
    fn attributed_gap_projection_refuses_cache_and_replays_receipt() {
        use brokk_bifrost_analysis::analyzer::common::{
            QueryCacheCell, capture_query_cache_build, replayable_query_cache_cell,
        };
        use brokk_bifrost_analysis::analyzer::i_analyzer::QueryLookupProvenance;
        use brokk_bifrost_analysis::analyzer::{
            AnalyzerQueryScope, ProjectFile, QueryReadIncomplete,
        };
        use brokk_bifrost_go::packages::{GoReadGap, GoReadGapKind, GoWorkspacePathIndex};

        let project = fixture("");
        let workspace = project.workspace_analyzer(Default::default());
        let go =
            brokk_bifrost_analysis::analyzer::resolve_analyzer::<GoAnalyzer>(workspace.analyzer())
                .unwrap();
        let gap = QueryReadIncomplete::SemanticEvidenceGap("missing external type".into())
            .attributed(QueryLookupProvenance {
                file: ProjectFile::new(go.project().root(), "Lookup.java"),
                byte_span: 12..19,
                name: "Missing".into(),
                tier: "same-package",
            });
        let digest = |gaps: Vec<GoReadGap>| {
            GoWorkspacePathIndex::build(
                go.project(),
                |file| go.package_clause_of(file),
                &Default::default(),
                || gaps,
            )
            .read_answer()
        };
        let cell = QueryCacheCell::new();
        let (completion, receipt) = {
            let leader = AnalyzerQueryScope::capturing_read_incompleteness(go);
            let (completion, receipt) = capture_query_cache_build(go, || {
                replayable_query_cache_cell(go, &cell, || {
                    let captured = AnalyzerQueryScope::capturing_read_incompleteness(go);
                    // Inject a typed read failure in the same nested capture used
                    // by both production projections, before their answer hashing.
                    go.record_query_incomplete(gap.clone());
                    stable_completion(go, captured.captured_read_incompleteness())
                })
            });
            assert_eq!(
                leader.captured_read_incompleteness().as_slice(),
                std::slice::from_ref(&gap),
            );
            assert!(!receipt.is_complete());
            (completion, receipt)
        };
        assert!(
            cell.get().is_none(),
            "unsupported projection must not be retained"
        );
        assert_eq!(
            completion,
            [GoReadGap {
                kind: GoReadGapKind::SemanticEvidenceGap,
                detail: "missing external type".into(),
            }]
        );
        assert_ne!(digest(completion.clone()), digest(Vec::new()));
        assert_eq!(
            digest(completion.clone()),
            digest(stable_completion(
                go,
                vec![QueryReadIncomplete::SemanticEvidenceGap(
                    "missing external type".into()
                ),]
            ))
        );
        // Exercise the typed receipt replay used by failed-wave followers,
        // without depending on scheduler timing to enter the same wave.
        let ((), follower_reads) = capture_query_reads(go, || {
            let follower = AnalyzerQueryScope::capturing_read_incompleteness(go);
            assert!(follower.captured_read_incompleteness().is_empty());
            receipt.replay();
            assert_eq!(follower.captured_read_incompleteness(), [gap]);
        });
        assert!(follower_reads.reuse_refused());

        // Plain supported gaps still produce a reusable cache entry.
        let plain_cell = QueryCacheCell::new();
        let (_, reads) = capture_query_reads(go, || {
            replayable_query_cache_cell(go, &plain_cell, || {
                go.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                    "plain".into(),
                ));
                stable_completion(
                    go,
                    vec![QueryReadIncomplete::SemanticEvidenceGap("plain".into())],
                )
            })
        });
        assert!(plain_cell.get().is_some());
        assert!(!reads.reuse_refused());
    }

    fn fixture(other: &str) -> crate::inline_project::BuiltInlineTestProject {
        InlineTestProject::with_language(Language::Go)
            .with_git()
            .file("go.mod", "module example.com/repro\n\ngo 1.23\n")
            .file(
                "target.go",
                "package repro\ntype Target struct {}\nfunc (Target) Ping() {}\n",
            )
            .file("other.go", other)
            .build()
    }

    /// The selection reads an evaluation over `workspace` records when it asks
    /// for the Go build profile.
    fn recorded_selection_reads(
        workspace: &brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer,
    ) -> Vec<ReadKey> {
        use brokk_bifrost_analysis::analyzer::read_ledger::EvaluationSelectionReads;
        use brokk_bifrost_core::analyzer::carried_context::EvaluationExecution;
        let go =
            brokk_bifrost_analysis::analyzer::resolve_analyzer::<GoAnalyzer>(workspace.analyzer())
                .unwrap();
        let evaluation = std::sync::Arc::new(EvaluationExecution::default());
        let _installed = evaluation.install();
        let _scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(go);
        assert!(go.native_context_base_profile().is_some());
        evaluation
            .selection_reads::<EvaluationSelectionReads>()
            .keys()
    }

    #[test]
    #[hardwon("#11482: aggregate evaluation omitted discovered Go membership")]
    fn go_evaluation_collects_build_membership() {
        use brokk_bifrost_analysis::analyzer::read_ledger::EvaluationSelectionReads;
        use brokk_bifrost_core::analyzer::carried_context::EvaluationExecution;
        let project = fixture("package repro\n");
        let workspace = project.workspace_analyzer(Default::default());
        let go =
            brokk_bifrost_analysis::analyzer::resolve_analyzer::<GoAnalyzer>(workspace.analyzer())
                .unwrap();
        let evaluation = std::sync::Arc::new(EvaluationExecution::default());
        let _installed = evaluation.install();
        let _scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(go);
        assert!(go.native_context_base_profile().is_some());
        let scans = go.membership_scan_count_for_test();
        assert!(scans > 0);
        for _ in 0..3 {
            assert!(go.native_context_base_profile().is_some());
        }
        assert_eq!(go.membership_scan_count_for_test(), scans);
        let reads = evaluation
            .selection_reads::<EvaluationSelectionReads>()
            .keys();
        assert!(
            reads.iter().any(|key| matches!(
                key,
                ReadKey::Lookup {
                    question: LookupQuestion::WorkspaceFact {
                        family: WorkspaceFactFamily::GoBuildSelection,
                        subject: FactSubject::NamedMember { .. },
                        ..
                    },
                    ..
                }
            )),
            "{reads:?}"
        );
    }

    #[test]
    #[hardwon("#11482: equal Go profiles concealed changed discovered membership")]
    fn go_membership_answer_changes_with_same_profile() {
        let project = fixture("package repro\n");
        let before_workspace = project.workspace_analyzer(Default::default());
        let before = brokk_bifrost_analysis::analyzer::resolve_analyzer::<GoAnalyzer>(
            before_workspace.analyzer(),
        )
        .unwrap();
        let base = before.native_context_base_profile().unwrap();
        let snapshots = before.inner.selected_workspace_snapshots();
        let snapshot = &snapshots["go"];
        let domains = before
            .inner
            .analyzer_store()
            .go_selected_domain_keys(snapshot, &base)
            .unwrap();
        let (directory, work) = &domains[0];
        let first =
            selected_domain_membership_answer(before, snapshot, &base, directory, work).unwrap();
        project.file("added.go").write("package repro\n").unwrap();
        let after_workspace = project.workspace_analyzer(Default::default());
        let after = brokk_bifrost_analysis::analyzer::resolve_analyzer::<GoAnalyzer>(
            after_workspace.analyzer(),
        )
        .unwrap();
        assert_eq!(after.native_context_base_profile(), Some(base));
        let snapshots = after.inner.selected_workspace_snapshots();
        assert_ne!(
            Some(first),
            selected_domain_membership_answer(after, &snapshots["go"], &base, directory, work)
        );
        let mut added_domains = domains.clone();
        added_domains.push(("new-domain".into(), "".into()));
        added_domains.sort();
        assert_ne!(
            domain_set_answer(&domains),
            domain_set_answer(&added_domains)
        );
    }

    #[test]
    #[hardwon("#11482: membership certificate ignored package completeness and provider state")]
    fn go_membership_answer_changes_with_package_state_under_same_names() {
        let project = fixture("package repro\n");
        let workspace = project.workspace_analyzer(Default::default());
        let go =
            brokk_bifrost_analysis::analyzer::resolve_analyzer::<GoAnalyzer>(workspace.analyzer())
                .unwrap();
        let base = go.native_context_base_profile().unwrap();
        let snapshots = go.inner.selected_workspace_snapshots();
        let snapshot = &snapshots["go"];
        let domains = go
            .inner
            .analyzer_store()
            .go_selected_domain_keys(snapshot, &base)
            .unwrap();
        let (directory, work) = &domains[0];
        let answer = || {
            selected_domain_membership_answer(go, snapshot, &base, directory, work)
                .expect("membership answers")
        };
        // Package and file names stay; each step changes discovery state that a
        // dependency leaving the module cache would change, and must move the answer.
        let mut previous = answer();
        for change in [
            "UPDATE go_package_instances SET complete=1-complete",
            "UPDATE go_package_instances SET gaps=jsonb(json_insert(json(gaps),'$[#]',json('{\"code\":\"gone\"}')))",
            "UPDATE go_package_instances SET provider_module_version=coalesce(provider_module_version,'')||'v9'",
            "UPDATE go_context_publications SET complete=1-complete",
        ] {
            go.inner.analyzer_store().conn.execute(move |conn| {
                assert!(conn.execute(change, []).unwrap() > 0, "{change}");
            });
            let next = answer();
            assert_ne!(previous, next, "{change}");
            previous = next;
        }
    }

    #[test]
    #[hardwon("#11482: aggregate replay never checked the Go selection reads it consumed")]
    fn go_selection_reads_replay_by_recomputing_each_answer() {
        use brokk_bifrost_analysis::analyzer::read_verification::{
            BaseView, ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers,
            verify_selection_reads,
        };
        use brokk_bifrost_analysis::analyzer::reuse_verdict::SelectionEvidence;
        let project = fixture("package repro\n");
        let workspace = project.workspace_analyzer(Default::default());
        let reads = recorded_selection_reads(&workspace);
        let changed = ChangedFacts::between(&workspace, &workspace);
        let verify = |keys: &[ReadKey], view| {
            let reads = keys
                .iter()
                .cloned()
                .map(brokk_bifrost_analysis::analyzer::read_ledger::SelectionRead::keyed)
                .collect::<Vec<_>>();
            verify_selection_reads(
                &workspace,
                &changed,
                &reads,
                view,
                false,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            )
        };
        let moved = |key: &ReadKey| match key {
            ReadKey::Lookup { kind, question, .. } => ReadKey::Lookup {
                kind: *kind,
                question: question.clone(),
                digest: StableDigest::from_array([9; 32]),
            },
            other => panic!("selection reads are lookups: {other:?}"),
        };
        let named = |key: &ReadKey, wanted: &str| {
            matches!(key, ReadKey::Lookup { question: LookupQuestion::WorkspaceFact {
                subject: FactSubject::Named { name }, ..
            }, .. } if name.as_ref() == wanted)
        };
        let profile = reads
            .iter()
            .filter(|key| named(key, "profile"))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(profile.len(), 1, "{reads:?}");
        assert!(reads.iter().any(|key| named(key, "domains")), "{reads:?}");
        // The head is the base: every recorded answer is recomputed, including
        // the discovered membership, and holds.
        assert_eq!(
            verify(&reads, BaseView::HeadIsBase),
            SelectionEvidence::Complete
        );
        // A head that may differ can speak only for the answer that tree
        // content cannot change. The profile is environment and configuration.
        assert_eq!(
            verify(&reads, BaseView::HeadMayDiffer),
            SelectionEvidence::Incomplete
        );
        assert_eq!(
            verify(&profile, BaseView::HeadMayDiffer),
            SelectionEvidence::Complete
        );
        // A changed environment changes the recorded profile answer.
        assert_eq!(
            verify(&[moved(&profile[0])], BaseView::HeadMayDiffer),
            SelectionEvidence::Incomplete
        );
        // An equal profile does not vouch for the membership it selected.
        for key in reads.iter().filter(|key| !named(key, "profile")) {
            let mut membership = reads.clone();
            membership.retain(|read| read != key);
            membership.push(moved(key));
            assert_eq!(
                verify(&membership, BaseView::HeadIsBase),
                SelectionEvidence::Incomplete,
                "{key:?}"
            );
        }
    }

    fn go_is_installed() -> bool {
        std::process::Command::new("go")
            .arg("version")
            .output()
            .is_ok()
    }

    /// Whether the recorded `reads` still hold on `head`, for a base row produced
    /// over an export of the key's tree and a head that may differ from it.
    fn export_base_holds(
        head: &brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer,
        base: &brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer,
        reads: &[ReadKey],
    ) -> bool {
        use brokk_bifrost_analysis::analyzer::read_verification::{
            BaseView, ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers,
            verify_selection_reads,
        };
        use brokk_bifrost_analysis::analyzer::reuse_verdict::SelectionEvidence;
        let reads = reads
            .iter()
            .cloned()
            .map(brokk_bifrost_analysis::analyzer::read_ledger::SelectionRead::keyed)
            .collect::<Vec<_>>();
        verify_selection_reads(
            head,
            &ChangedFacts::between(base, head),
            &reads,
            BaseView::HeadMayDiffer,
            true,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        ) == SelectionEvidence::Complete
    }

    fn provider_directories(reads: &[ReadKey]) -> Vec<Box<str>> {
        provider_names(reads, PROVIDER_STATE_MEMBER)
    }

    fn provider_names(reads: &[ReadKey], wanted: &str) -> Vec<Box<str>> {
        reads
            .iter()
            .filter_map(|key| match key {
                ReadKey::Lookup {
                    question:
                        LookupQuestion::WorkspaceFact {
                            subject: FactSubject::NameGroupMember { names, member },
                            ..
                        },
                    ..
                } if member.as_ref() == wanted => Some(names.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// Go membership and domains are a function of the exported tree and the
    /// profile, and the directories `go list` read outside the checkout are
    /// verified against the head's environment (#11607).
    #[test]
    #[hardwon(
        "#11607: Go domains and membership replayed only against the base tree, so every edited head evaluated its base again"
    )]
    fn an_export_base_replays_over_an_edited_head_while_the_environment_holds() {
        if !go_is_installed() {
            return;
        }
        let build = |other: &str| {
            InlineTestProject::with_language(Language::Go)
                .with_git()
                .file("go.mod", "module example.com/repro\n\ngo 1.23\n")
                .file(
                    "target.go",
                    "package repro\nimport \"fmt\"\nfunc Target() { fmt.Println() }\n",
                )
                .file("other.go", other)
                .build()
        };
        let base_project = build("package repro\n");
        let head_project = build("package repro\nfunc Edited() {}\n");
        let base = base_project.workspace_analyzer(Default::default());
        let head = head_project.workspace_analyzer(Default::default());
        let reads = recorded_selection_reads(&base);
        assert!(
            provider_names(&reads, PROVIDER_STANDARD_MEMBER)
                .iter()
                .any(|directory| {
                    std::path::Path::new(directory.as_ref())
                        .file_name()
                        .is_some_and(|name| name == "fmt")
                }),
            "the standard-library packages go list read are recorded: {reads:?}"
        );
        assert!(export_base_holds(&head, &base, &reads));

        // A toolchain that reports another default for a key outside the old
        // profile is a different environment.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let scripts = tempfile::tempdir().unwrap();
            let wrapper = scripts.path().join("go-other-default");
            std::fs::write(
                &wrapper,
                format!("#!/bin/sh\n{OTHER_TOOLCHAIN_GO_ENV_SCRIPT}\n"),
            )
            .unwrap();
            std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
            let mut config = brokk_bifrost_core::analyzer::config::AnalyzerConfig::default();
            config.go.dependency_discovery.go_executable = Some(wrapper);
            let other_toolchain = head_project.workspace_analyzer(config);
            assert!(!export_base_holds(&other_toolchain, &base, &reads));
        }
    }

    /// A module `go list` found outside the checkout (a replace target here, as a
    /// module cache directory is) is verified by its directory's state.
    #[test]
    #[hardwon(
        "#11607: a module provider's directory was not part of the recorded Go membership's environment"
    )]
    fn a_changed_module_provider_directory_refuses_an_export_base() {
        if !go_is_installed() {
            return;
        }
        let dependency = tempfile::tempdir().unwrap();
        std::fs::write(
            dependency.path().join("go.mod"),
            "module example.com/dep\n\ngo 1.23\n",
        )
        .unwrap();
        std::fs::write(
            dependency.path().join("dep.go"),
            "package dep\nfunc Run() {}\n",
        )
        .unwrap();
        let project = InlineTestProject::with_language(Language::Go)
            .with_git()
            .file(
                "go.mod",
                format!(
                    "module example.com/repro\n\ngo 1.23\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => {}\n",
                    dependency.path().display()
                ),
            )
            .file(
                "main.go",
                "package repro\nimport \"example.com/dep\"\nfunc Main() { dep.Run() }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(Default::default());
        let reads = recorded_selection_reads(&workspace);
        let dependency_directory = dependency.path().to_string_lossy().into_owned();
        assert!(
            provider_directories(&reads)
                .iter()
                .any(|directory| **directory == *dependency_directory),
            "the module provider's directory is recorded: {reads:?}"
        );
        assert!(export_base_holds(&workspace, &workspace, &reads));
        std::fs::write(
            dependency.path().join("dep.go"),
            "package dep\nimport \"os\"\nfunc Run() { os.Exit(0) }\n",
        )
        .unwrap();
        assert!(!export_base_holds(&workspace, &workspace, &reads));
    }

    /// A project that requires `example.com/dep` through a local `replace` outside
    /// the checkout, importing `import`. The dependency has a root package, a
    /// subpackage, a header file and a `go.mod`.
    fn replaced_dependency_project(
        dependency: &std::path::Path,
        import: &str,
        call: &str,
    ) -> crate::inline_project::BuiltInlineTestProject {
        std::fs::create_dir_all(dependency.join("sub")).unwrap();
        std::fs::write(
            dependency.join("go.mod"),
            "module example.com/dep\n\ngo 1.23\n",
        )
        .unwrap();
        std::fs::write(dependency.join("dep.go"), "package dep\nfunc Run() {}\n").unwrap();
        std::fs::write(dependency.join("dep.h"), "#define DEP 1\n").unwrap();
        std::fs::write(
            dependency.join("sub/sub.go"),
            "package sub\nfunc Run() {}\n",
        )
        .unwrap();
        InlineTestProject::with_language(Language::Go)
            .with_git()
            .file(
                "go.mod",
                format!(
                    "module example.com/repro\n\ngo 1.23\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => {}\n",
                    dependency.display()
                ),
            )
            .file(
                "main.go",
                format!("package repro\nimport \"{import}\"\nfunc Main() {{ {call} }}\n"),
            )
            .build()
    }

    /// The module metadata and the non-Go files `go list` reads for a provider
    /// outside the checkout decide what it selects, so an edit that keeps every
    /// length and every Go file's bytes must still change the answer.
    #[test]
    #[hardwon(
        "#11607: review found a local replacement's go.mod edit left the Go provider-state answer unchanged"
    )]
    fn an_edited_replacement_go_mod_or_header_refuses_an_export_base() {
        if !go_is_installed() {
            return;
        }
        let dependency = tempfile::tempdir().unwrap();
        let project =
            replaced_dependency_project(dependency.path(), "example.com/dep", "dep.Run()");
        let workspace = project.workspace_analyzer(Default::default());
        let reads = recorded_selection_reads(&workspace);
        assert!(
            export_base_holds(&workspace, &workspace, &reads),
            "{reads:?}"
        );
        // The required Go version changes, and no length does.
        std::fs::write(
            dependency.path().join("go.mod"),
            "module example.com/dep\n\ngo 1.24\n",
        )
        .unwrap();
        assert!(!export_base_holds(&workspace, &workspace, &reads));
        std::fs::write(
            dependency.path().join("go.mod"),
            "module example.com/dep\n\ngo 1.23\n",
        )
        .unwrap();
        assert!(export_base_holds(&workspace, &workspace, &reads));
        // A header the tool reads for build constraints.
        std::fs::write(dependency.path().join("dep.h"), "#define DEP 2\n").unwrap();
        assert!(!export_base_holds(&workspace, &workspace, &reads));
    }

    /// With only a subpackage imported, the module's root lies outside every
    /// recorded package directory.
    #[test]
    #[hardwon(
        "#11607: review found a local replacement's go.mod edit left the Go provider-state answer unchanged when only a subpackage was imported"
    )]
    fn an_edited_module_root_go_mod_refuses_when_only_a_subpackage_is_imported() {
        if !go_is_installed() {
            return;
        }
        let dependency = tempfile::tempdir().unwrap();
        let project =
            replaced_dependency_project(dependency.path(), "example.com/dep/sub", "sub.Run()");
        let workspace = project.workspace_analyzer(Default::default());
        let reads = recorded_selection_reads(&workspace);
        let sub = dependency.path().join("sub").to_string_lossy().into_owned();
        assert!(
            provider_directories(&reads)
                .iter()
                .all(|directory| **directory != *dependency.path().to_string_lossy()),
            "the module root is not a recorded package directory: {reads:?}"
        );
        assert!(
            provider_directories(&reads)
                .iter()
                .any(|directory| **directory == *sub),
            "{reads:?}"
        );
        assert_eq!(
            provider_names(&reads, PROVIDER_ROOTS_MEMBER),
            vec![Box::<str>::from(dependency.path().to_string_lossy())],
            "{reads:?}"
        );
        assert!(export_base_holds(&workspace, &workspace, &reads));
        std::fs::write(
            dependency.path().join("go.mod"),
            "module example.com/dep\n\ngo 1.24\n",
        )
        .unwrap();
        assert!(!export_base_holds(&workspace, &workspace, &reads));
        std::fs::write(
            dependency.path().join("go.mod"),
            "module example.com/dep\n\ngo 1.23\n",
        )
        .unwrap();
        assert!(export_base_holds(&workspace, &workspace, &reads));
        // A go.sum that appears is module metadata too.
        std::fs::write(dependency.path().join("go.sum"), "").unwrap();
        assert!(!export_base_holds(&workspace, &workspace, &reads));
    }

    /// A package in a local replacement outside the checkout that embeds
    /// `assets/*`, next to a nested module that the embed cannot reach.
    #[test]
    #[hardwon(
        "#11607: review found an embed target in a dependency subdirectory left the Go provider-state answer unchanged"
    )]
    fn an_embed_target_in_a_dependency_subdirectory_refuses_an_export_base() {
        if !go_is_installed() {
            return;
        }
        let dependency = tempfile::tempdir().unwrap();
        let root = dependency.path();
        std::fs::create_dir_all(root.join("assets")).unwrap();
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("go.mod"), "module example.com/dep\n\ngo 1.23\n").unwrap();
        std::fs::write(
            root.join("dep.go"),
            "package dep\nimport \"embed\"\n//go:embed assets/*\nvar Assets embed.FS\n",
        )
        .unwrap();
        std::fs::write(root.join("assets/a.txt"), "a\n").unwrap();
        std::fs::write(
            root.join("nested/go.mod"),
            "module example.com/dep/nested\n\ngo 1.23\n",
        )
        .unwrap();
        std::fs::write(root.join("nested/inner.txt"), "one\n").unwrap();
        let project = InlineTestProject::with_language(Language::Go)
            .with_git()
            .file(
                "go.mod",
                format!(
                    "module example.com/repro\n\ngo 1.23\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => {}\n",
                    root.display()
                ),
            )
            .file(
                "main.go",
                "package repro\nimport \"example.com/dep\"\nfunc Main() { _ = dep.Assets }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(Default::default());
        let reads = recorded_selection_reads(&workspace);
        assert_eq!(
            provider_names(&reads, PROVIDER_STATE_MEMBER),
            vec![Box::<str>::from(root.to_string_lossy())],
            "{reads:?}"
        );
        assert!(
            export_base_holds(&workspace, &workspace, &reads),
            "{reads:?}"
        );

        // A new file the pattern matches.
        std::fs::write(root.join("assets/b.txt"), "b\n").unwrap();
        assert!(!export_base_holds(&workspace, &workspace, &reads));
        std::fs::remove_file(root.join("assets/b.txt")).unwrap();
        assert!(export_base_holds(&workspace, &workspace, &reads));
        // The only match removed: the tool reports the pattern as an error.
        std::fs::remove_file(root.join("assets/a.txt")).unwrap();
        assert!(!export_base_holds(&workspace, &workspace, &reads));
        std::fs::write(root.join("assets/a.txt"), "a\n").unwrap();
        assert!(export_base_holds(&workspace, &workspace, &reads));
        // An empty directory matched by the pattern: the tool reports that it
        // contains no embeddable files (review of #11607).
        std::fs::create_dir(root.join("assets/empty")).unwrap();
        assert!(!export_base_holds(&workspace, &workspace, &reads));
        std::fs::remove_dir(root.join("assets/empty")).unwrap();
        assert!(export_base_holds(&workspace, &workspace, &reads));

        // A nested module is a different module: the embed cannot cross into
        // it, so its files are not read. Its boundary is.
        std::fs::write(root.join("nested/inner.txt"), "two\n").unwrap();
        std::fs::write(root.join("nested/more.txt"), "more\n").unwrap();
        std::fs::write(
            root.join("nested/go.mod"),
            "module example.com/dep/nested\n\ngo 1.24\n",
        )
        .unwrap();
        assert!(export_base_holds(&workspace, &workspace, &reads));
        std::fs::remove_file(root.join("nested/go.mod")).unwrap();
        assert!(!export_base_holds(&workspace, &workspace, &reads));
    }

    /// Module graph loading reads the go.mod of a replacement target whose
    /// packages nothing imports, and its requirements can raise the version
    /// selected for a module that is imported. Nothing in the checkout pins
    /// that file.
    #[test]
    #[hardwon("#11607: review found an unused local replacement's go.mod was not a recorded input")]
    fn an_edited_unused_replacement_go_mod_refuses_an_export_base() {
        if !go_is_installed() {
            return;
        }
        let dependency = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(
            dependency.path().join("go.mod"),
            "module example.com/dep\n\ngo 1.23\n",
        )
        .unwrap();
        std::fs::write(dependency.path().join("dep.go"), "package dep\n").unwrap();
        let project = InlineTestProject::with_language(Language::Go)
            .with_git()
            .file(
                "go.mod",
                format!(
                    "module example.com/repro\n\ngo 1.23\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => {}\n",
                    dependency.path().display()
                ),
            )
            .file(
                "main.go",
                "package repro\nimport \"fmt\"\nfunc Main() { fmt.Println() }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(Default::default());
        let reads = recorded_selection_reads(&workspace);
        assert!(
            provider_directories(&reads).is_empty(),
            "no module package is imported: {reads:?}"
        );
        assert!(
            provider_names(&reads, PROVIDER_ROOTS_MEMBER)
                .iter()
                .any(|root| **root == *dependency.path().to_string_lossy()),
            "the replacement's directory is a recorded root: {reads:?}"
        );
        assert!(
            export_base_holds(&workspace, &workspace, &reads),
            "{reads:?}"
        );

        // An edit outside the replacement, and to a file of its that no
        // selected package reads, leaves the base reused.
        std::fs::write(elsewhere.path().join("unrelated.go"), "package other\n").unwrap();
        std::fs::write(
            dependency.path().join("dep.go"),
            "package dep\nfunc Edited() {}\n",
        )
        .unwrap();
        assert!(export_base_holds(&workspace, &workspace, &reads));

        // The requirement can select a different version of another module.
        std::fs::write(
            dependency.path().join("go.mod"),
            "module example.com/dep\n\ngo 1.23\n\nrequire example.com/other v1.2.0\n",
        )
        .unwrap();
        assert!(!export_base_holds(&workspace, &workspace, &reads));
        std::fs::write(
            dependency.path().join("go.mod"),
            "module example.com/dep\n\ngo 1.23\n",
        )
        .unwrap();
        assert!(export_base_holds(&workspace, &workspace, &reads));
    }

    /// In workspace mode cmd/go does not require go.sum entries for the go.mod
    /// files of the module graph and discovery turns the checksum database off,
    /// so a module-cache go.mod that no selected package reads is not pinned by
    /// anything recorded. The same layout without a go.work is reused.
    #[test]
    #[hardwon(
        "#11607: review found go.work domains leave unselected module-cache go.mod files unverified"
    )]
    fn a_go_work_domain_refuses_an_export_base() {
        if !go_is_installed() {
            return;
        }
        let holds = |go_work: Option<&str>| {
            let mut project = InlineTestProject::with_language(Language::Go)
                .with_git()
                .file("go.mod", "module example.com/repro\n\ngo 1.23\n")
                .file(
                    "main.go",
                    "package repro\nimport \"fmt\"\nfunc Main() { fmt.Println() }\n",
                );
            if let Some(go_work) = go_work {
                project = project.file("go.work", go_work);
            }
            let project = project.build();
            let workspace = project.workspace_analyzer(Default::default());
            let reads = recorded_selection_reads(&workspace);
            export_base_holds(&workspace, &workspace, &reads)
        };
        assert!(holds(None), "the layout without go.work is reusable");
        assert!(
            !holds(Some("go 1.23\n\nuse .\n")),
            "a go.work domain is not export-verifiable"
        );
    }

    fn questions() -> Vec<(WorkspaceFactFamily, FactSubject)> {
        vec![
            (
                WorkspaceFactFamily::GoWorkspaceIndexes,
                FactSubject::Named {
                    name: "example.com/repro.Target".into(),
                },
            ),
            (WorkspaceFactFamily::GoWorkspaceIndexes, FactSubject::Whole),
            (WorkspaceFactFamily::GoWorkspacePaths, FactSubject::Whole),
            (WorkspaceFactFamily::GoImportFacts, FactSubject::Whole),
            (WorkspaceFactFamily::GoReverseImports, FactSubject::Whole),
            (
                WorkspaceFactFamily::GoBuildSelection,
                FactSubject::Named {
                    name: "profile".into(),
                },
            ),
            (
                WorkspaceFactFamily::GoBuildSelection,
                FactSubject::Named {
                    name: "error".into(),
                },
            ),
        ]
    }

    fn verify_fact(
        head: &brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer,
        base: &brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer,
        family: WorkspaceFactFamily,
        subject: FactSubject,
        recorded: StableDigest,
    ) -> brokk_bifrost_analysis::analyzer::ReadVerdict {
        use brokk_bifrost_analysis::analyzer::{
            ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers,
        };
        let key = ReadKey::lookup(
            LookupKind::WorkspaceFact,
            LookupQuestion::WorkspaceFact {
                family,
                language: Language::Go,
                subject,
            },
            recorded,
        );
        brokk_bifrost_analysis::analyzer::read_verification::verify_read_set(
            head,
            &ChangedFacts::between(base, head),
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            &[key],
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        )
    }

    #[test]
    #[hardwon(
        "#8799: review found the workspace path answer certified index data but not its replayed stable gaps"
    )]
    fn go_workspace_fact_revalidation_tracks_stable_completion_both_ways() {
        for (family, file, initial) in [
            (
                WorkspaceFactFamily::GoWorkspacePaths,
                "other_test.go",
                "package repro\n",
            ),
            (
                WorkspaceFactFamily::GoImportFacts,
                "other.go",
                "// no package clause\n",
            ),
        ] {
            let project = InlineTestProject::with_language(Language::Go)
                .with_git()
                .file("go.mod", "module example.com/repro\n\ngo 1.23\n")
                .file("target.go", "package repro\ntype Target struct {}\n")
                .file(file, initial)
                .build();
            let base = project.workspace_analyzer(Default::default());
            let before = {
                let (_, reads) = capture_query_reads(base.analyzer(), || match family {
                    WorkspaceFactFamily::GoWorkspacePaths => {
                        brokk_bifrost_analysis::analyzer::resolve_analyzer::<GoAnalyzer>(
                            base.analyzer(),
                        )
                        .unwrap()
                        .workspace_path_index();
                    }
                    WorkspaceFactFamily::GoImportFacts => {
                        brokk_bifrost_analysis::analyzer::resolve_analyzer::<GoAnalyzer>(
                            base.analyzer(),
                        )
                        .unwrap()
                        .import_facts();
                    }
                    _ => unreachable!(),
                });
                assert!(reads.keys().iter().any(|key| matches!(key, ReadKey::Lookup { kind: LookupKind::WorkspaceFact, question: LookupQuestion::WorkspaceFact { family: recorded, .. }, .. } if *recorded == family)), "{family:?}: {:?}", reads.keys());
                answer(base.analyzer(), family, Language::Go, &FactSubject::Whole).unwrap()
            };
            project
                .file(file)
                .write(format!("//{}\n", "x".repeat(16_001)))
                .unwrap();
            let gap = project.workspace_analyzer(Default::default());
            let during =
                { answer(gap.analyzer(), family, Language::Go, &FactSubject::Whole).unwrap() };
            assert_ne!(
                verify_fact(&gap, &base, family, FactSubject::Whole, before),
                brokk_bifrost_analysis::analyzer::ReadVerdict::Unchanged,
                "added gap: {family:?}"
            );
            project.file(file).write(initial).unwrap();
            let restored = project.workspace_analyzer(Default::default());
            assert_ne!(
                verify_fact(&restored, &gap, family, FactSubject::Whole, during),
                brokk_bifrost_analysis::analyzer::ReadVerdict::Unchanged,
                "removed gap: {family:?}"
            );
        }
    }

    #[test]
    fn workspace_authorities_repeat_the_same_snapshot_answers() {
        let project = fixture("package repro\ntype Other interface { Missing() }\n");
        let go = GoAnalyzer::new(project.project_dyn());
        go.selection_error_write().clear();
        for (family, subject) in questions() {
            let first = answer(&go, family, Language::Go, &subject).expect("Go fact answer");
            assert_eq!(
                Some(first),
                answer(&go, family, Language::Go, &subject),
                "{family:?} {subject:?}"
            );
            for _ in 0..2 {
                let (_, reads) =
                    capture_query_reads(&go, || answer(&go, family, Language::Go, &subject));
                assert_eq!(reads.unattributed_reads(), 0);
                assert!(reads.keys().iter().any(|key| matches!(key, ReadKey::Lookup { kind: LookupKind::WorkspaceFact, question: LookupQuestion::WorkspaceFact { family: recorded, subject: recorded_subject, .. }, digest: recorded_answer } if *recorded == family && *recorded_subject == subject && *recorded_answer == first)), "{family:?}: {:?}", reads.keys());
            }
        }
    }

    #[test]
    fn a_comment_above_declarations_preserves_workspace_authority_answers() {
        let project = fixture("package repro\ntype Other interface { Missing() }\n");
        let base = GoAnalyzer::new(project.project_dyn());
        base.selection_error_write().clear();
        let before = questions()
            .into_iter()
            .map(|(family, subject)| answer(&base, family, Language::Go, &subject))
            .collect::<Vec<_>>();
        project.file("other.go").write("// comment before the first declaration\npackage repro\ntype Other interface { Missing() }\n").unwrap();
        let head = GoAnalyzer::new(project.project_dyn());
        head.selection_error_write().clear();
        let after = questions()
            .into_iter()
            .map(|(family, subject)| answer(&head, family, Language::Go, &subject))
            .collect::<Vec<_>>();
        assert_eq!(before, after);
    }

    #[test]
    #[hardwon("#7496: a warm hierarchy answer ignored an unimported interface edit")]
    fn an_unimported_interface_edit_changes_the_hierarchy_certificate() {
        let project = fixture("package repro\ntype Other interface { Missing() }\n");
        let base = GoAnalyzer::new(project.project_dyn());
        let subject = FactSubject::Named {
            name: "example.com/repro.Target".into(),
        };
        let before = answer(
            &base,
            WorkspaceFactFamily::GoWorkspaceIndexes,
            Language::Go,
            &subject,
        )
        .unwrap();
        let base_workspace = project.workspace_analyzer(Default::default());
        assert_eq!(
            verify_fact(
                &base_workspace,
                &base_workspace,
                WorkspaceFactFamily::GoWorkspaceIndexes,
                subject.clone(),
                before
            ),
            brokk_bifrost_analysis::analyzer::ReadVerdict::Unchanged
        );
        project
            .file("other.go")
            .write("package repro\ntype Other interface { Ping() }\n")
            .unwrap();
        let head_workspace = project.workspace_analyzer(Default::default());
        assert_ne!(
            verify_fact(
                &head_workspace,
                &base_workspace,
                WorkspaceFactFamily::GoWorkspaceIndexes,
                subject.clone(),
                before
            ),
            brokk_bifrost_analysis::analyzer::ReadVerdict::Unchanged
        );
        let head = GoAnalyzer::new(project.project_dyn());
        assert_ne!(
            Some(before),
            answer(
                &head,
                WorkspaceFactFamily::GoWorkspaceIndexes,
                Language::Go,
                &subject
            )
        );
    }

    #[test]
    fn an_unimported_package_edit_changes_complete_inventory_and_usage_answers() {
        let project = InlineTestProject::with_language(Language::Go)
            .with_git()
            .file("go.mod", "module example.com/repro\n\ngo 1.23\n")
            .file("target.go", "package repro\ntype Target struct {}\n")
            .file(
                "extra/other_test.go",
                "package extra\ntype Other struct {}\n",
            )
            .build();
        let base = GoAnalyzer::new(project.project_dyn());
        let subjects = [
            (WorkspaceFactFamily::GoWorkspacePaths, FactSubject::Whole),
            (WorkspaceFactFamily::GoImportFacts, FactSubject::Whole),
            (WorkspaceFactFamily::GoWorkspaceIndexes, FactSubject::Whole),
        ];
        let before = subjects
            .iter()
            .map(|(family, subject)| answer(&base, *family, Language::Go, subject).unwrap())
            .collect::<Vec<_>>();
        let base_workspace = project.workspace_analyzer(Default::default());
        project
            .file("extra/other_test.go")
            .write("package extra_test\ntype Other struct {}\n")
            .unwrap();
        let head_workspace = project.workspace_analyzer(Default::default());
        let head = GoAnalyzer::new(project.project_dyn());
        for ((family, subject), before) in subjects.iter().zip(before) {
            assert_ne!(
                verify_fact(
                    &head_workspace,
                    &base_workspace,
                    *family,
                    subject.clone(),
                    before
                ),
                brokk_bifrost_analysis::analyzer::ReadVerdict::Unchanged,
                "{family:?}"
            );
            assert_ne!(
                Some(before),
                answer(&head, *family, Language::Go, subject),
                "{family:?}"
            );
        }
    }

    #[test]
    fn an_unimported_importer_edit_changes_the_reverse_import_certificate() {
        let project = InlineTestProject::with_language(Language::Go)
            .with_git()
            .file("go.mod", "module example.com/repro\n\ngo 1.23\n")
            .file("target.go", "package repro\ntype Target struct {}\n")
            .file("other/other.go", "package other\n")
            .build();
        let base = project.workspace_analyzer(Default::default());
        let family = WorkspaceFactFamily::GoReverseImports;
        let subject = FactSubject::Whole;
        let before = answer(base.analyzer(), family, Language::Go, &subject).unwrap();
        assert_eq!(
            verify_fact(&base, &base, family, subject.clone(), before),
            brokk_bifrost_analysis::analyzer::ReadVerdict::Unchanged
        );
        project
            .file("other/other.go")
            .write("package other\nimport \"example.com/repro\"\nvar value repro.Target\n")
            .unwrap();
        let head = project.workspace_analyzer(Default::default());
        let after = answer(head.analyzer(), family, Language::Go, &subject)
            .expect("the changed head has a complete reverse-import answer");
        assert_ne!(before, after);
        assert_ne!(
            verify_fact(&head, &base, family, subject, before),
            brokk_bifrost_analysis::analyzer::ReadVerdict::Unchanged
        );
    }

    #[test]
    fn selected_build_state_changes_its_own_named_answers() {
        let project = fixture("package repro\n");
        let go = GoAnalyzer::new(project.project_dyn());
        go.selection_error_write().clear();
        let profile = FactSubject::Named {
            name: "profile".into(),
        };
        let error = FactSubject::Named {
            name: "error".into(),
        };
        let before_profile = answer(
            &go,
            WorkspaceFactFamily::GoBuildSelection,
            Language::Go,
            &profile,
        )
        .unwrap();
        let before_error = answer(
            &go,
            WorkspaceFactFamily::GoBuildSelection,
            Language::Go,
            &error,
        )
        .unwrap();
        *go.profile_write() = Some([41; 32]);
        *go.selection_error_write() = "selected build refused".into();
        assert_ne!(
            Some(before_profile),
            answer(
                &go,
                WorkspaceFactFamily::GoBuildSelection,
                Language::Go,
                &profile
            )
        );
        let (failed, reads) = capture_query_reads(&go, || {
            answer(
                &go,
                WorkspaceFactFamily::GoBuildSelection,
                Language::Go,
                &error,
            )
        });
        assert!(
            failed.is_none(),
            "failure text has no position-free certificate: {before_error:?}"
        );
        assert!(reads.unattributed_reads() > 0);
    }

    #[test]
    #[hardwon(
        "#2445: cloning Go build-selection memos recorded answers during recording-view construction"
    )]
    fn copying_an_analyzer_does_not_consult_build_selection() {
        let project = fixture("package repro\n");
        let go = GoAnalyzer::new(project.project_dyn());
        *go.profile_write() = Some([41; 32]);
        *go.selection_error_write() = "selected build refused".into();
        let ((cloned, rebound), reads) = capture_query_reads(&go, || {
            (go.clone(), go.clone_with_project(project.project_dyn()))
        });
        assert!(reads.keys().is_empty(), "{:?}", reads.keys());
        assert_eq!(reads.unattributed_reads(), 0);
        for copy in [cloned, rebound] {
            assert_eq!(*copy.profile_read(), Some([41; 32]));
            assert_eq!(&*copy.selection_error_read(), "selected build refused");
            *copy.profile_write() = Some([42; 32]);
            *copy.selection_error_write() = "copy selection changed".into();
            assert_eq!(*go.profile_read(), Some([41; 32]));
            assert_eq!(&*go.selection_error_read(), "selected build refused");
        }
    }

    #[test]
    #[hardwon("#2445: Go workspace-index builds rejected correctly transported source reads")]
    fn workspace_index_worker_records_files_into_the_owners_capture() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::read_key_recorded_on_active_ledgers;
        use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, QueryScope};
        use brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo;
        use brokk_bifrost_go::graph::resolver::{GoGraphSource, build_go_workspace_indexes};

        let project = fixture("package repro\ntype Other interface { Ping() }\n");
        let go = GoAnalyzer::new(project.project_dyn());
        let file = project.file("target.go");
        let target = go
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "Target")
            .unwrap();
        let files = go.get_analyzed_files().into_iter().collect::<Vec<_>>();
        let memo = PoolSafeMemo::new();
        // Capture the actual builder's reads before the authority replaces
        // them with its answer Fact. The pool transports the owner's frame.
        let (indexes, reads) = capture_query_reads(&go, || {
            memo.get_or_try_build_on_dedicated_pool(|| {
                assert!(go.current_thread_read_ledger().is_none());
                let scope = AnalyzerQueryScope::new(&go);
                let source = GoGraphSource {
                    token: scope.token(),
                    index: &go,
                    imports: &go,
                    type_aliases: &go,
                    workspace_paths: &go.workspace_path_index(),
                    package_clauses: &go,
                    source_facts: &go,
                };
                let indexes = build_go_workspace_indexes(source, &files)?;
                let oid = go.inner.resolve_live_oid_for_file(&file).unwrap();
                assert!(read_key_recorded_on_active_ledgers(
                    &go,
                    &go.inner.file_read_key(
                        &file,
                        oid,
                        brokk_bifrost_core::gitblob::ParseVariant::Empty
                    )
                ));
                assert!(scope.store_error().is_none());
                Ok::<_, brokk_bifrost_go::graph::resolver::GoGraphBuildError>(indexes)
            })
            .unwrap()
        });
        assert!(indexes.hierarchy.supports(&target));
        assert!(reads.keys().iter().any(
            |key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == "target.go")
        ));
        assert_eq!(reads.unattributed_reads(), 0);
    }

    #[test]
    fn changed_module_receipts_cannot_certify_a_retained_generation() {
        let project = fixture("package repro\n");
        let retained = GoAnalyzer::new(project.project_dyn());
        let target = project.file("target.go");
        assert!(!retained.declarations(&target).is_empty());
        project
            .file("go.mod")
            .write("module example.com/changed\n\ngo 1.23\n")
            .unwrap();
        let head = GoAnalyzer::new(project.project_dyn());
        assert!(!head.declarations(&target).is_empty());
        let (units, reads) = capture_query_reads(&retained, || retained.declarations(&target));
        assert!(!units.is_empty());
        assert!(
            reads.unattributed_reads() > 0,
            "new raw probes do not describe the retained generation's cached identities"
        );
    }

    #[test]
    #[hardwon("#7496: restored module inputs hid a source memo fill under another namespace")]
    fn restored_module_inputs_do_not_certify_a_mismounted_cache_fill() {
        use super::super::source_storage::CanonicalGoSourceFacts;
        let project = fixture("package repro\n");
        let mut retained = GoAnalyzer::new(project.project_dyn());
        let target = project.file("target.go");
        retained.inner.clear_retained_file_states_for_test();
        project
            .file("go.mod")
            .write("module example.com/changed\n\ngo 1.23\n")
            .unwrap();
        let changed = GoAnalyzer::new(project.project_dyn());
        assert!(!changed.declarations(&target).is_empty());
        let (facts, reads) = capture_query_reads(&retained, || {
            retained
                .inner
                .canonical_go_source_facts(&target, &retained.memo_caches.source_facts)
        });
        assert!(facts.is_some());
        assert!(reads.unattributed_reads() > 0);
        project
            .file("go.mod")
            .write("module example.com/repro\n\ngo 1.23\n")
            .unwrap();
        let restored = GoAnalyzer::new(project.project_dyn());
        assert!(!restored.declarations(&target).is_empty());
        let (facts, reads) = capture_query_reads(&retained, || {
            retained
                .inner
                .canonical_go_source_facts(&target, &retained.memo_caches.source_facts)
        });
        let cached = facts.unwrap();
        let fresh = restored
            .inner
            .canonical_go_source_facts(&target, &restored.memo_caches.source_facts)
            .unwrap();
        assert!(
            cached.declaration_units == fresh.declaration_units || reads.unattributed_reads() > 0,
            "cached identities were mounted from different inputs: cached {:?}, fresh {:?}",
            cached.declaration_units,
            fresh.declaration_units
        );
    }

    #[test]
    fn an_unready_hierarchy_inventory_refuses_reuse() {
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module \"invalid path\"\n")
            .file("target.go", "package repro\ntype Target struct {}\n")
            .build();
        let go = GoAnalyzer::new(project.project_dyn());
        let (value, reads) = capture_query_reads(&go, || {
            answer(
                &go,
                WorkspaceFactFamily::GoWorkspaceIndexes,
                Language::Go,
                &FactSubject::Named {
                    name: "repro.Target".into(),
                },
            )
        });
        assert!(value.is_none());
        assert!(reads.unattributed_reads() > 0);
    }

    #[test]
    fn warm_import_memos_replay_module_files_and_absent_probes() {
        let project = InlineTestProject::with_language(Language::Go)
            .with_git()
            .file("go.mod", "module example.com/repro\n\ngo 1.23\n")
            .file("pkg/target.go", "package pkg\ntype Target struct {}\n")
            .file(
                "main.go",
                "package main\nimport \"example.com/repro/pkg\"\nvar value pkg.Target\n",
            )
            .build();
        let go = GoAnalyzer::new(project.project_dyn());
        let main = project.file("main.go");
        let target = project.file("pkg/target.go");
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(&go, || {
                let units = go.imported_code_units_of(&main);
                assert!(!units.is_empty());
                go.referencing_files_of(&target)
            });
            assert_eq!(reads.unattributed_reads(), 0);
            assert!(reads.keys().iter().any(|key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == "go.mod")), "{:?}", reads.keys());
            assert!(reads.keys().iter().any(|key| matches!(key, ReadKey::PathAbsent { rel_path, .. } if rel_path.as_ref() == "pkg/go.mod")), "{:?}", reads.keys());
        }
        // A retained source-fact hit also uses the identity-input hook.
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(&go, || go.declarations(&target));
            assert!(reads.keys().iter().any(|key| matches!(key, ReadKey::PathAbsent { rel_path, .. } if rel_path.as_ref() == "pkg/go.mod")));
        }
    }
}
