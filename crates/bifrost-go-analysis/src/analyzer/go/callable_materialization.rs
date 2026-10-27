//! Demand-scoped executable materialization for exact Go callable artifacts.
//!
//! The source identity binders in `source_identity` prove that a descriptor
//! names one fresh AST node. This module performs the separate execution step:
//! it lowers one exact selected file, locates the proven procedure in that
//! artifact, and returns request-local handles. Nothing here is retained in a
//! workspace cache or durable native target.

use super::super::GoPinnedPackage;

use crate::analyzer::go::source_identity::GoBoundAnonymousCallableIdentity;

use crate::analyzer::go::source_identity::GoFunctionTypeShape;

use crate::analyzer::go::source_identity::GoSourceAnchor;

use crate::analyzer::go::source_identity::GoSourceDeclarationIdentity;

use crate::analyzer::go::source_identity::GoSourceDeclarationKind;

use crate::analyzer::go::source_identity::bind_go_anonymous_callable_identity_in_selected_file;

use crate::analyzer::go::semantic::lower_exact_go_file;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::semantic::ArtifactCallableTarget;

use brokk_bifrost_analysis::analyzer::semantic::CaptureBinding;

use brokk_bifrost_analysis::analyzer::semantic::MemoryLocationId;

use brokk_bifrost_analysis::analyzer::semantic::MemoryLocationKind;

use brokk_bifrost_analysis::analyzer::semantic::ProcedureHandle;

use brokk_bifrost_semantic::analyzer::semantic::ir::ProcedureKind;

use brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact;

use brokk_bifrost_analysis::analyzer::semantic::SemanticCapability;

use brokk_bifrost_analysis::analyzer::semantic::SemanticOutcome;

use brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError;

use brokk_bifrost_analysis::analyzer::semantic::SemanticRequest;

use brokk_bifrost_analysis::analyzer::semantic::SemanticWork;

use brokk_bifrost_analysis::analyzer::semantic::WorkspaceMountId;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ExactArtifact;

use brokk_bifrost_core::hash::HashSet;
use std::path::Path;
use std::sync::Arc;

/// One executable capture destination in the freshly materialized anonymous
/// procedure. The ID is scoped to the returned `SemanticArtifact`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GoCaptureSlot {
    destination: MemoryLocationId,
}

impl GoCaptureSlot {
    pub const fn destination(self) -> MemoryLocationId {
        self.destination
    }
}

/// The exact child slots and native creation bindings for one materialized
/// anonymous callable. The plan owns only request-local handles and IDs.
#[derive(Clone)]
pub struct GoCaptureSlotPlan {
    target: ProcedureHandle,
    slots: Box<[GoCaptureSlot]>,
}

impl GoCaptureSlotPlan {
    pub fn target(&self) -> &ProcedureHandle {
        &self.target
    }

    pub fn slots(&self) -> &[GoCaptureSlot] {
        &self.slots
    }

    /// Return all native per-creation bindings after checking that they fill
    /// exactly the target's capture slots in this same artifact.
    pub fn bind_creation_captures(
        &self,
        factory: &ProcedureHandle,
    ) -> Result<Box<[CaptureBinding]>, GoCallableCaptureBindingError> {
        let Some(parent) = self.target.semantics().lexical_parent() else {
            return Err(GoCallableCaptureBindingError::WrongFactory);
        };
        if parent != factory.id() || !Arc::ptr_eq(factory.artifact(), self.target.artifact()) {
            return Err(GoCallableCaptureBindingError::WrongFactory);
        }
        if self
            .target
            .semantics()
            .gaps()
            .iter()
            .any(|gap| gap.capability == SemanticCapability::Captures)
        {
            return Err(GoCallableCaptureBindingError::IncompleteCaptureProof);
        }
        let destinations = self
            .slots
            .iter()
            .map(|slot| slot.destination)
            .collect::<HashSet<_>>();
        let bindings = factory
            .semantics()
            .captures()
            .iter()
            .filter(|binding| binding.target == self.target.id())
            .cloned()
            .collect::<Vec<_>>();
        if bindings.len() != self.slots.len() {
            return Err(GoCallableCaptureBindingError::IncompleteCaptureProof);
        }
        let mut bound_destinations = HashSet::default();
        for binding in &bindings {
            if !destinations.contains(&binding.destination) {
                return Err(GoCallableCaptureBindingError::ForeignDestination);
            }
            if !bound_destinations.insert(binding.destination) {
                return Err(GoCallableCaptureBindingError::DuplicateDestination);
            }
        }
        if bound_destinations != destinations {
            return Err(GoCallableCaptureBindingError::IncompleteCaptureProof);
        }
        Ok(bindings.into_boxed_slice())
    }
}

/// Why native per-creation captures could not be bound to the fresh target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoCallableCaptureBindingError {
    WrongFactory,
    IncompleteCaptureProof,
    ForeignDestination,
    DuplicateDestination,
}

/// An executable anonymous callable plus its immediate factory parent and
/// source proof. The artifact and handles are request-local.
pub struct GoMaterializedAnonymousCallable {
    artifact: Arc<SemanticArtifact>,
    callable: ProcedureHandle,
    factory: ProcedureHandle,
    source: GoBoundAnonymousCallableIdentity,
    captures: GoCaptureSlotPlan,
}

impl GoMaterializedAnonymousCallable {
    pub fn artifact(&self) -> &Arc<SemanticArtifact> {
        &self.artifact
    }

    pub fn callable(&self) -> &ProcedureHandle {
        &self.callable
    }

    pub fn factory(&self) -> &ProcedureHandle {
        &self.factory
    }

    pub fn source(&self) -> &GoBoundAnonymousCallableIdentity {
        &self.source
    }

    pub fn captures(&self) -> &GoCaptureSlotPlan {
        &self.captures
    }

    pub fn bind_per_creation_captures(
        &self,
    ) -> Result<Box<[CaptureBinding]>, GoCallableCaptureBindingError> {
        self.captures.bind_creation_captures(&self.factory)
    }
}

/// Materialize exactly one selected anonymous target after rebinding its
/// descriptor to a fresh AST and lowering the complete selected file.
pub fn materialize_go_anonymous_callable(
    file: &ProjectFile,
    mounted_workspace: WorkspaceMountId,
    artifact: &ExactArtifact,
    package: &GoPinnedPackage,
    target: &ArtifactCallableTarget,
    max_nodes: usize,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<GoMaterializedAnonymousCallable>, SemanticProviderError> {
    let identity = target.identity();
    if !identity_matches_file(identity.anchor.file.as_str(), file) {
        return Ok(SemanticOutcome::Unknown {
            partial: None,
            work: SemanticWork::default(),
        });
    }
    let node_limit = max_nodes;
    let bound = match bind_go_anonymous_callable_identity_in_selected_file(
        artifact,
        package,
        identity,
        node_limit,
        Some(request.cancellation),
    ) {
        Ok(bound) => bound,
        Err(error) => return Ok(source_proof_outcome(error, request)),
    };
    let mut work = SemanticWork::default();
    charge_materialization_work(
        request,
        SemanticWork {
            nested_entries: bound.visited_nodes(),
            ..SemanticWork::default()
        },
        &mut work,
    );
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work,
        });
    }
    charge_materialization_work(
        request,
        SemanticWork {
            nested_entries: artifact.source_entries().len(),
            ..SemanticWork::default()
        },
        &mut work,
    );
    let Some(source) = exact_source_for_target(artifact, &identity.anchor.file) else {
        return Ok(SemanticOutcome::Unknown {
            partial: None,
            work,
        });
    };
    let lowered = lower_exact_go_file(file, mounted_workspace, source, artifact, package, request)?;
    let lowered_work = lowered.work();
    let SemanticOutcome::Complete {
        value: artifact, ..
    } = lowered
    else {
        return Ok(map_incomplete_lowering(lowered, work));
    };
    work = work.conservative_add(lowered_work);
    let procedure_scan_work = SemanticWork {
        nested_entries: artifact.procedures().len(),
        ..SemanticWork::default()
    };
    charge_materialization_work(request, procedure_scan_work, &mut work);
    let Some(callable_anchor) = native_anchor_for_source_anchor(&artifact, &bound.source().anchor)
    else {
        return Ok(SemanticOutcome::Unknown {
            partial: None,
            work,
        });
    };
    charge_materialization_work(request, procedure_scan_work, &mut work);
    let Some(callable) = unique_procedure_handle(&artifact, callable_anchor, ProcedureKind::Lambda)
    else {
        return Ok(SemanticOutcome::Unknown {
            partial: None,
            work,
        });
    };
    let Some(parent_id) = callable.semantics().lexical_parent() else {
        return Ok(SemanticOutcome::Unknown {
            partial: None,
            work,
        });
    };
    let Some(factory) = artifact.procedure_handle(parent_id) else {
        return Ok(SemanticOutcome::Unknown {
            partial: None,
            work,
        });
    };
    let Some(expected_parent) = bound.source().lexical_owner_chain.last() else {
        return Ok(SemanticOutcome::Unknown {
            partial: None,
            work,
        });
    };
    let Some(expected_parent_anchor) = native_anchor_for_source_anchor(&artifact, expected_parent)
    else {
        return Ok(SemanticOutcome::Unknown {
            partial: None,
            work,
        });
    };
    charge_materialization_work(request, procedure_scan_work, &mut work);
    let capture_check_work = SemanticWork {
        nested_entries: 1,
        gaps: callable.semantics().gaps().len(),
        memory_locations: callable.semantics().memory_locations().len(),
        ..SemanticWork::default()
    };
    charge_materialization_work(request, capture_check_work, &mut work);
    if factory.semantics().locator().anchor() != expected_parent_anchor {
        return Ok(SemanticOutcome::Unknown {
            partial: None,
            work,
        });
    }
    let Some(captures) = capture_slot_plan(&callable) else {
        return Ok(SemanticOutcome::Unknown {
            partial: None,
            work,
        });
    };
    Ok(SemanticOutcome::Complete {
        value: GoMaterializedAnonymousCallable {
            artifact,
            callable: callable.clone(),
            factory,
            source: bound,
            captures: GoCaptureSlotPlan {
                target: callable,
                slots: captures,
            },
        },
        work,
    })
}

fn identity_matches_file(identity_file: &str, file: &ProjectFile) -> bool {
    Path::new(identity_file)
        .components()
        .eq(file.rel_path().components())
}

fn exact_source_for_target<'a>(artifact: &'a ExactArtifact, file: &str) -> Option<&'a str> {
    let mut entries = artifact
        .source_entries()
        .iter()
        .filter(|entry| entry.relative_path() == file);
    let entry = entries.next()?;
    if entries.next().is_some() {
        return None;
    }
    std::str::from_utf8(entry.bytes()).ok()
}

/// Find the actual anchor minted by the fresh lowerer for one source range.
/// The Go descriptor supplies only a byte range; this helper never constructs
/// a native anchor because its line/column and occurrence are owned by the
/// lowerer's AST walk.
fn native_anchor_for_source_anchor(
    artifact: &Arc<SemanticArtifact>,
    source: &GoSourceAnchor,
) -> Option<brokk_bifrost_analysis::analyzer::semantic::SourceAnchor> {
    let (Ok(start), Ok(end)) = (
        u32::try_from(source.byte_range.start),
        u32::try_from(source.byte_range.end),
    ) else {
        return None;
    };
    let mut matches = artifact
        .procedures()
        .iter()
        .filter(|procedure| {
            let anchor = procedure.locator().anchor();
            procedure.locator().path().as_str() == source.file
                && anchor.span().start_byte() == start
                && anchor.span().end_byte() == end
        })
        .map(|procedure| procedure.locator().anchor());
    let anchor = matches.next()?;
    matches.next().is_none().then_some(anchor)
}

fn unique_procedure_handle(
    artifact: &Arc<SemanticArtifact>,
    anchor: brokk_bifrost_analysis::analyzer::semantic::SourceAnchor,
    kind: ProcedureKind,
) -> Option<ProcedureHandle> {
    let mut matches = artifact
        .procedures()
        .iter()
        .filter(|procedure| procedure.kind() == kind && procedure.locator().anchor() == anchor)
        .map(|procedure| procedure.id());
    let id = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    artifact.procedure_handle(id)
}

fn capture_slot_plan(callable: &ProcedureHandle) -> Option<Box<[GoCaptureSlot]>> {
    if callable
        .semantics()
        .gaps()
        .iter()
        .any(|gap| gap.capability == SemanticCapability::Captures)
    {
        return None;
    }
    let parent = callable.semantics().lexical_parent()?;
    let mut slots = callable
        .semantics()
        .memory_locations()
        .iter()
        .filter_map(|location| match location.kind {
            MemoryLocationKind::Capture { lexical_parent, .. } if lexical_parent == parent => {
                Some(GoCaptureSlot {
                    destination: location.id,
                })
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    slots.sort_unstable_by_key(|slot| slot.destination);
    if slots
        .windows(2)
        .any(|slots| slots[0].destination == slots[1].destination)
    {
        return None;
    }
    Some(slots.into_boxed_slice())
}

fn charge_materialization_work(
    request: &mut SemanticRequest<'_>,
    added: SemanticWork,
    work: &mut SemanticWork,
) {
    *work = work.conservative_add(added);
    request.budget.charge_work(added);
}

fn source_proof_outcome<T>(
    error: crate::analyzer::go::source_identity::GoAnonymousCallableIdentityBindingError,
    request: &mut SemanticRequest<'_>,
) -> SemanticOutcome<T> {
    let visited_nodes = match error {
        crate::analyzer::go::source_identity::GoAnonymousCallableIdentityBindingError::Cancelled {
            visited_nodes,
        }
        | crate::analyzer::go::source_identity::GoAnonymousCallableIdentityBindingError::NodeBudgetExhausted {
            visited_nodes,
            ..
        }
        | crate::analyzer::go::source_identity::GoAnonymousCallableIdentityBindingError::SourceDiscoveryIncomplete {
            visited_nodes,
        }
        | crate::analyzer::go::source_identity::GoAnonymousCallableIdentityBindingError::IdentityNotFound {
            visited_nodes,
        }
        | crate::analyzer::go::source_identity::GoAnonymousCallableIdentityBindingError::AmbiguousIdentity {
            visited_nodes,
        } => visited_nodes,
        crate::analyzer::go::source_identity::GoAnonymousCallableIdentityBindingError::ArtifactMismatch
        | crate::analyzer::go::source_identity::GoAnonymousCallableIdentityBindingError::PackageMismatch => 0,
    };
    let work = SemanticWork {
        nested_entries: visited_nodes,
        ..SemanticWork::default()
    };
    request.budget.charge_work(work);
    if matches!(
        error,
        crate::analyzer::go::source_identity::GoAnonymousCallableIdentityBindingError::Cancelled { .. }
    ) || request.cancellation.is_cancelled()
    {
        SemanticOutcome::Cancelled {
            partial: None,
            work,
        }
    } else {
        SemanticOutcome::Unknown {
            partial: None,
            work,
        }
    }
}

fn map_incomplete_lowering<T>(
    outcome: SemanticOutcome<Arc<SemanticArtifact>>,
    prior_work: SemanticWork,
) -> SemanticOutcome<T> {
    match outcome {
        SemanticOutcome::Complete { .. } => {
            unreachable!("complete lowering is selected before incomplete mapping")
        }
        SemanticOutcome::Ambiguous { work, .. } => SemanticOutcome::Unknown {
            partial: None,
            work: prior_work.conservative_add(work),
        },
        SemanticOutcome::Unknown { work, .. } => SemanticOutcome::Unknown {
            partial: None,
            work: prior_work.conservative_add(work),
        },
        SemanticOutcome::Unsupported {
            capability, work, ..
        } => SemanticOutcome::Unsupported {
            capability,
            partial: None,
            work: prior_work.conservative_add(work),
        },
        SemanticOutcome::Unproven { work, .. } => SemanticOutcome::Unknown {
            partial: None,
            work: prior_work.conservative_add(work),
        },
        SemanticOutcome::ExceededBudget { exceeded, work, .. } => SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: prior_work.conservative_add(work),
        },
        SemanticOutcome::Cancelled { work, .. } => SemanticOutcome::Cancelled {
            partial: None,
            work: prior_work.conservative_add(work),
        },
    }
}

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::attach_dispatch_provenance;

use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::dispatch_result_work;

use brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::dispatch::scoped_call_dispatch_gap;

use brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::dispatch::scoped_procedure_dispatch_gap;

use brokk_bifrost_semantic::analyzer::semantic::ir::CallSiteHandle;

use brokk_bifrost_analysis::analyzer::semantic::CandidateCoverage;

use brokk_bifrost_analysis::analyzer::semantic::DispatchCandidate;

use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::DispatchResult;

use brokk_bifrost_semantic::analyzer::semantic::ir::EvidenceCompleteness;

use brokk_bifrost_semantic::analyzer::semantic::ir::ProofStatus;

use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;

use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle;

use brokk_bifrost_analysis::analyzer::semantic::split_canonical_qualified_callee;

use brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind;

use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;

pub(crate) trait GoCallableMaterialization {
    /// Materialize one exact named Go factory from its activated source.
    ///
    /// The exact factory declaration is selected by the resolver and the
    /// activated member publication. Source lowering then proves the factory's
    /// actual return and capture behavior; declaration facts do not stand in
    /// for execution and callable-values rows are not required.
    fn materialize_go_callable_factory(
        &self,
        call: &CallSiteHandle,
        proof: &ExactExternalCallProof,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<SemanticOutcome<DispatchResult>>, SemanticProviderError>;
}

impl GoCallableMaterialization for WorkspaceSemanticOracle<'_> {
    fn materialize_go_callable_factory(
        &self,
        call: &CallSiteHandle,
        proof: &ExactExternalCallProof,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<SemanticOutcome<DispatchResult>>, SemanticProviderError> {
        use crate::analyzer::go::package_identity::GoOverlayPackages;
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            CatalogGoSourceReadLimits, CatalogGoSourceRequest, Locator, MemberKind,
            SemanticModelProof, SemanticModelSymbolKind,
        };
        if call.procedure().artifact().key().language() != SemanticLanguage::Standard(Language::Go)
            || proof.call_application() != CallApplicationKind::PackageFunction
        {
            return Ok(None);
        }
        let Some(snapshot) = self.active_semantic_model_snapshot() else {
            return Ok(None);
        };
        let Some(overlay) = snapshot.semantic_model_overlay() else {
            return Ok(None);
        };
        let active = snapshot.active_models();
        let Some(reader) = active.source_reader() else {
            return Ok(None);
        };
        let packages = GoOverlayPackages::new(Some(overlay));
        let Some((package_path, member)) =
            split_canonical_qualified_callee(proof.canonical_callee(), Language::Go)
        else {
            return Ok(None);
        };
        let Some(factory) = packages.visible_member(&package_path, &member) else {
            return Ok(None);
        };
        if factory.provenance.active_model_set_hash != active.active_model_set_hash()
            || factory.provenance.ambiguous
            || factory.provenance.proof != SemanticModelProof::ExactArtifact
            || factory.provenance.activation.status != "active"
            || factory.kind != SemanticModelSymbolKind::Function
            || factory.name != member
            || !factory.is_static()
            || factory.has_receiver()
        {
            return Ok(None);
        }
        let (Some(factory_path), Some(factory_symbol), Some(artifact_sha256)) = (
            factory.locator_path.as_deref(),
            factory.locator_symbol.as_deref(),
            factory
                .provenance
                .activation
                .matched_evidence
                .artifact_sha256
                .as_deref(),
        ) else {
            return Ok(None);
        };
        let member_candidates = GoOverlayPackages::member_candidates(&package_path, &member);
        if !member_candidates
            .iter()
            .any(|candidate| candidate == factory_symbol)
        {
            return Ok(None);
        }

        let matched = active.members_with_id(&factory.provenance.record_id);
        let lookup_work = SemanticWork {
            nested_entries: matched
                .candidates_examined
                .saturating_add(matched.fallback_candidates_examined),
            ..SemanticWork::default()
        };
        let mut work = SemanticWork::default();
        charge_materialization_work(request, lookup_work, &mut work);
        let [activated] = matched.records.as_slice() else {
            return Ok(None);
        };
        if !go_factory_publication_matches(&factory, &activated.shard)
            || activated.record.name != member
            || activated.record.member_kind != MemberKind::Function
            || activated.record.owner != factory.owner_id.as_deref().unwrap_or_default()
            || activated
                .shard
                .guard_excludes(activated.record.guard.as_ref())
        {
            return Ok(None);
        }
        let Locator::Artifact {
            path: activated_path,
            symbol: activated_symbol,
        } = &activated.record.locator
        else {
            return Ok(None);
        };
        if activated_path != factory_path
            || activated_symbol != factory_symbol
            || activated.shard.matched_evidence.artifact_sha256.as_deref() != Some(artifact_sha256)
        {
            return Ok(None);
        }
        let Some(signature) = activated.record.signature.as_ref() else {
            return Ok(None);
        };
        if factory.structured_signature() != Some(signature) {
            return Ok(None);
        }

        let source_request = CatalogGoSourceRequest {
            manifest_digest: &activated.shard.manifest.content_sha256,
            shard_id: activated.shard.descriptor.shard_id.as_str(),
            artifact_sha256,
            package_import_path: &package_path,
            file: factory_path,
        };
        // The catalog returns owned source buffers, not just scan visits.
        // Keep their admission separate from non-refusing scan telemetry and
        // release it after every return, cancellation, and failed lowering.
        let mut staged_budget = request.budget.clone();
        let mut temporary_source = None;
        let result = {
            let mut staged_request = request.staged(&mut staged_budget);
            let request = &mut staged_request;
            (|| {
                let source = match reader.read_go_source(
                    &source_request,
                    CatalogGoSourceReadLimits {
                        max_files: request.budget.remaining().nested_entries,
                        max_source_bytes: request.budget.remaining().source_bytes as u64,
                        max_path_depth: CatalogGoSourceReadLimits::default().max_path_depth,
                    },
                    request.cancellation,
                ) {
                    Ok(source) => source,
                    Err(brokk_bifrost_analysis::analyzer::semantic_model::CatalogError::Cancelled) => {
                        return Ok(Some(SemanticOutcome::Cancelled {
                            partial: None,
                            work,
                        }));
                    }
                    Err(brokk_bifrost_analysis::analyzer::semantic_model::CatalogError::SourceBudgetExhausted {
                        max_files,
                        max_source_bytes,
                    }) => {
                        let refused = SemanticWork {
                            source_bytes: usize::try_from(max_source_bytes)
                                .unwrap_or(usize::MAX)
                                .saturating_add(1),
                            nested_entries: max_files.saturating_add(1),
                            ..SemanticWork::default()
                        };
                        let exceeded = request
                            .budget
                            .check_admission(refused)
                            .expect_err("catalog source buffers exceed the resident allowance");
                        return Ok(Some(SemanticOutcome::ExceededBudget {
                            partial: None,
                            exceeded,
                            work,
                        }));
                    }
                    Err(error) => {
                        return Err(SemanticProviderError::internal(format!(
                            "exact Go callable source demand failed: {error}"
                        )));
                    }
                };
                let Some(source) = source else {
                    return Ok(None);
                };
                if source.artifact.sha256() != artifact_sha256 {
                    return Ok(None);
                }
                let source_work = SemanticWork {
                    source_bytes: source
                        .artifact
                        .source_entries()
                        .iter()
                        .map(|entry| entry.bytes().len())
                        .sum(),
                    nested_entries: source.artifact.source_entries().len()
                        + source.packages.len()
                        + source
                            .packages
                            .iter()
                            .map(|package| package.files.len())
                            .sum::<usize>(),
                    owned_text_bytes: source
                        .artifact
                        .source_entries()
                        .iter()
                        .map(|entry| entry.relative_path().len())
                        .sum::<usize>()
                        + source
                            .packages
                            .iter()
                            .map(|package| {
                                package.import_path.len()
                                    + package.name.len()
                                    + package.files.iter().map(String::len).sum::<usize>()
                            })
                            .sum::<usize>(),
                    ..SemanticWork::default()
                };
                if let Err(exceeded) = request.budget.admit(source_work) {
                    return Ok(Some(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    }));
                }
                temporary_source = Some(source_work);
                charge_materialization_work(request, source_work, &mut work);
                let Some(package) = source.packages.iter().find(|package| {
                    package.import_path == package_path
                        && package.files.iter().any(|file| file == factory_path)
                }) else {
                    return Ok(None);
                };
                let selected_package = GoPinnedPackage {
                    import_path: package.import_path.clone(),
                    name: package.name.clone(),
                    files: vec![factory_path.to_owned()],
                };
                let identities = crate::analyzer::go::analyze_go_package_source_identities(
                    &source.artifact,
                    &selected_package,
                    usize::MAX,
                    Some(request.cancellation),
                );
                let identity_work = SemanticWork {
                    nested_entries: identities.visited_nodes,
                    ..SemanticWork::default()
                };
                charge_materialization_work(request, identity_work, &mut work);
                if request.cancellation.is_cancelled()
                    || identities.gaps.iter().any(|gap| {
                        gap.kind == crate::analyzer::go::GoSourceIdentityGapKind::Cancelled
                    })
                {
                    return Ok(Some(SemanticOutcome::Cancelled {
                        partial: None,
                        work,
                    }));
                }
                if !identities.is_source_discovery_complete() {
                    return Ok(None);
                }
                let mut factory_identities = identities.identities.iter().filter(|identity| {
                    identity.artifact_sha256 == artifact_sha256
                        && identity.package_import_path == package_path
                        && identity.anchor.file == factory_path
                        && identity.anchor.kind == GoSourceDeclarationKind::Function
                        && identity.lexical_owner_chain.is_empty()
                        && identity
                            .name
                            .as_ref()
                            .is_some_and(|name| name.text == member)
                        && identity.callable_signature.is_some()
                });
                let Some(identity) = factory_identities.next() else {
                    return Ok(None);
                };
                if factory_identities.next().is_some()
                    || !go_factory_location_matches(&factory, identity)
                {
                    return Ok(None);
                }
                let Some(callable_signature) = identity.callable_signature.as_ref() else {
                    return Ok(None);
                };
                if !go_factory_signature_matches(callable_signature, signature, &identity.anchor) {
                    return Ok(None);
                }
                let Some(source_text) = exact_source_for_target(&source.artifact, factory_path)
                else {
                    return Ok(None);
                };

                let root = self.workspace().analyzer().project().root();
                let file = ProjectFile::new(root.to_path_buf(), factory_path);
                let lowered = lower_exact_go_file(
                    &file,
                    WorkspaceMountId::from_root(root),
                    source_text,
                    &source.artifact,
                    package,
                    request,
                )?;
                let lowered_work = lowered.work();
                let SemanticOutcome::Complete {
                    value: artifact, ..
                } = lowered
                else {
                    return Ok(Some(map_incomplete_lowering(lowered, work)));
                };
                work = work.conservative_add(lowered_work);
                let procedure_scan_work = SemanticWork {
                    nested_entries: artifact.procedures().len(),
                    ..SemanticWork::default()
                };
                charge_materialization_work(request, procedure_scan_work, &mut work);
                let Some(factory_anchor) =
                    native_anchor_for_source_anchor(&artifact, &identity.anchor)
                else {
                    return Ok(None);
                };
                let Some(factory_handle) =
                    unique_procedure_handle(&artifact, factory_anchor, ProcedureKind::Function)
                else {
                    return Ok(None);
                };

                let semantic_call = call
                    .procedure()
                    .semantics()
                    .call_site(call.id())
                    .expect("validated call handle");
                let mut candidates = vec![
                    DispatchCandidate::new(
                        factory_handle,
                        ProofStatus::Proven,
                        EvidenceCompleteness::Complete,
                        std::iter::empty(),
                        *self.limits(),
                    )
                    .map_err(|error| SemanticProviderError::internal(error.to_string()))?,
                ];
                let mut boundaries = Vec::new();
                attach_dispatch_provenance(
                    call,
                    &mut candidates,
                    &mut boundaries,
                    scoped_call_dispatch_gap(call.procedure().semantics(), semantic_call),
                    scoped_procedure_dispatch_gap(call.procedure()),
                    *self.limits(),
                )?;
                let result = DispatchResult::new(
                    call,
                    candidates,
                    boundaries,
                    CandidateCoverage::Exhaustive,
                    *self.limits(),
                )
                .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
                let result_work = dispatch_result_work(&result);
                work = work.conservative_add(result_work);
                if let Err(exceeded) = request.budget.admit(result_work) {
                    return Ok(Some(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    }));
                }
                Ok(Some(SemanticOutcome::Complete {
                    value: result,
                    work,
                }))
            })()
        };
        if let Some(census) = temporary_source {
            staged_budget.release_admission(census);
        }
        *request.budget = staged_budget;
        result
    }
}

fn go_factory_publication_matches(
    factory: &brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol,
    shard: &brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelShard,
) -> bool {
    let provenance = &factory.provenance;
    provenance.pack_digest == shard.manifest.semantic_sha256
        && provenance.pack_id == shard.manifest.pack_id
        && provenance.pack_version == shard.manifest.version
        && provenance.activation.source_id == shard.source_id
        && provenance.activation.matched_evidence
            == brokk_bifrost_analysis::analyzer::semantic_model::matched_evidence(
                &shard.matched_evidence,
            )
}

fn go_factory_location_matches(
    factory: &brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol,
    identity: &GoSourceDeclarationIdentity,
) -> bool {
    match &factory.location {
        brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelLocation::Authored(
            anchor,
        ) => {
            anchor.path == identity.anchor.file
                && anchor.range.start_byte == identity.anchor.byte_range.start
                && anchor.range.end_byte == identity.anchor.byte_range.end
        }
        brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelLocation::Model(_) => true,
    }
}

fn go_factory_signature_matches(
    shape: &GoFunctionTypeShape,
    signature: &brokk_bifrost_analysis::analyzer::semantic_model::Signature,
    anchor: &GoSourceAnchor,
) -> bool {
    let in_anchor = |node: &crate::analyzer::go::GoSourceTypeNode| {
        node.file == anchor.file
            && node.byte_range.start >= anchor.byte_range.start
            && node.byte_range.end <= anchor.byte_range.end
    };
    if shape.function_type.file != anchor.file
        || shape.function_type.byte_range.start < anchor.byte_range.start
        || shape.function_type.byte_range.end > anchor.byte_range.end
        || shape
            .parameters
            .iter()
            .any(|parameter| !in_anchor(&parameter.type_node))
        || shape
            .results
            .iter()
            .any(|result| !in_anchor(&result.type_node))
    {
        return false;
    }

    let source_parameter_arity = shape
        .parameters
        .iter()
        .map(|parameter| parameter.arity)
        .sum::<usize>();
    if source_parameter_arity != signature.parameters.len() {
        return false;
    }
    let mut parameter_offset = 0usize;
    for parameter in &shape.parameters {
        if parameter.arity == 0 {
            return false;
        }
        let Some(end) = parameter_offset.checked_add(parameter.arity) else {
            return false;
        };
        if end > signature.parameters.len()
            || signature.parameters[parameter_offset..end]
                .iter()
                .any(|model| model.variadic != parameter.variadic)
        {
            return false;
        }
        parameter_offset = end;
    }

    let source_result_arity = shape
        .results
        .iter()
        .map(|result| result.arity)
        .sum::<usize>();
    let model_result_arity = match signature.returns.as_ref() {
        None => 0,
        Some(brokk_bifrost_analysis::analyzer::semantic_model::TypeRef::Tuple { elements }) => {
            elements.len()
        }
        Some(_) => 1,
    };
    source_result_arity == model_result_arity
}
