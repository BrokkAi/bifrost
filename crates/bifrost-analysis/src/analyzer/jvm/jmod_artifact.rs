//! Bounded production of JVM declarations from a JDK's module archives.
//!
//! A JMOD is a ZIP-like archive whose Java class files live below `classes/`.
//! The source-set reader has already selected and read the exact regular files
//! under one approved JDK home; this producer is responsible only for bounded
//! ZIP walks and deterministic declaration-fact assembly.

use super::java_artifact::{
    JavaClassSurfaceOutcome, class_surface, class_surface_facts, zip_directory_status_with_limits,
};
use crate::CancellationToken;
use crate::analyzer::install_on_dedicated_build_pool;
use crate::analyzer::semantic_model::{
    ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest, AuthoredPayload,
    AuthoredSemanticModelPack, AuthoredShard, BoundedProducerDiagnostics, Completeness,
    ExactArtifact, ExactSourceEntry, ExternalArtifactKind, ExternalArtifactPackProducer,
    MemberFact, Producer, ProducerDiagnostic, ProducerDiagnosticSeverity, TypeFact, Visibility,
};
use crate::hash::{HashMap, HashSet};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use zip::ZipArchive;

const MAX_JMOD_ARCHIVE_ENTRIES: usize = 10_000;
const MAX_JMOD_CLASS_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_JMOD_TOTAL_CLASS_BYTES: u64 = 128 * 1024 * 1024;
const MAX_JMOD_CENTRAL_DIRECTORY_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct JdkJmodSetPackProducer;

impl ExternalArtifactPackProducer for JdkJmodSetPackProducer {
    fn produce_exact_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
    ) -> ArtifactProduction {
        unsupported_direct_production(request, limits)
    }

    fn produce_exact_artifact_with_cancellation(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ArtifactProduction {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: "artifact.cancelled".to_owned(),
                    location: None,
                    declaration: None,
                    message: "JDK JMOD production was cancelled".to_owned(),
                },
                limits,
            );
        }
        unsupported_direct_production(request, limits)
    }
}

impl JdkJmodSetPackProducer {
    /// Produce one pack from all JMOD ZIPs in an exact source-set artifact.
    ///
    /// The source-set digest and symlink checks happen before this method is
    /// called. Every selected JMOD is nevertheless validated independently so
    /// one malformed module cannot make a valid sibling look absent without a
    /// diagnostic.
    pub(crate) fn produce_loaded_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::JdkJmodSet {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: "artifact.kind".to_owned(),
                    location: None,
                    declaration: None,
                    message: "JDK JMOD producer requires a JDK JMOD source set".to_owned(),
                },
                limits,
            );
        }
        if request.activation.is_empty() {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: "jdk.activation.missing".to_owned(),
                    location: None,
                    declaration: None,
                    message: "JDK JMOD production requires an exact toolchain activation selector"
                        .to_owned(),
                },
                limits,
            );
        }
        if artifact.source_entries().is_empty() {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: "artifact.source_set_empty".to_owned(),
                    location: Some(artifact.path().to_string_lossy().into_owned()),
                    declaration: None,
                    message: "JDK JMOD production requires a non-empty exact source set".to_owned(),
                },
                limits,
            );
        }

        // The per-module archive read and class-table walk are the whole cost
        // of this producer, so they run on the process's parallelism. A module
        // that demands more of the artifact's record budget than the artifact
        // can spare is a different production from its own-budget counterpart,
        // and that case falls back to the single pass below.
        let loaded = match self.load_jmod_modules(artifact, limits, cancellation) {
            Some(loaded) => loaded,
            None => return cancelled_production(limits),
        };
        if loaded_demands_shared_budget(&loaded, limits) {
            return self.produce_single_pass(request, limits, cancellation, artifact);
        }
        self.assemble_loaded(request, artifact, limits, loaded, false)
    }

    /// Read and parse every module archive of the source set on the process's
    /// parallelism.
    ///
    /// One worker reads and parses one module under a record budget of its own.
    /// Whether the result can be assembled into the bytes a single pass would
    /// have produced is [`loaded_demands_shared_budget`]'s question.
    ///
    /// `None` means the production was cancelled.
    fn load_jmod_modules(
        &self,
        artifact: &ExactArtifact,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> Option<Vec<LoadedJmod>> {
        install_on_dedicated_build_pool(|| {
            artifact
                .source_entries()
                .par_iter()
                .map(|source_entry| {
                    let mut budget = RecordBudget::new(limits);
                    load_jmod_entry(source_entry, limits, cancellation, &mut budget)
                })
                .collect::<Vec<_>>()
        })
        .into_iter()
        .collect()
    }

    /// Produce with one record budget shared by every module of the artifact.
    ///
    /// Reading each module under a budget of its own cannot produce the bytes
    /// of a single pass once the artifact's shared budget is reached, because
    /// reaching it inside one module also stops the parse of every later
    /// module. That is rare: the default budget is several times what a real
    /// JDK demands. Exactness wins over the parallelism, so the producer
    /// repeats the read this way whenever the shared budget can bind.
    fn produce_single_pass(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
    ) -> ArtifactProduction {
        let mut budget = RecordBudget::new(limits);
        let mut loaded = Vec::with_capacity(artifact.source_entries().len());
        for source_entry in artifact.source_entries() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return cancelled_production(limits);
            }
            let Some(entry) = load_jmod_entry(source_entry, limits, cancellation, &mut budget)
            else {
                return cancelled_production(limits);
            };
            loaded.push(entry);
        }
        self.assemble_loaded(request, artifact, limits, loaded, budget.exhausted)
    }

    /// Insert every loaded module and finish the pack.
    ///
    /// The modules are assembled in source-entry order. That is what decides
    /// which of two disagreeing declarations is retained, and in which order
    /// the diagnostics that report them arrive.
    fn assemble_loaded(
        &self,
        request: &ArtifactProductionRequest,
        artifact: &ExactArtifact,
        limits: &ArtifactProducerLimits,
        loaded: Vec<LoadedJmod>,
        record_limit_hit: bool,
    ) -> ArtifactProduction {
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let mut modules = BTreeMap::<String, ModuleFacts>::new();
        for entry in loaded {
            diagnostics.absorb(entry.read_diagnostics);
            let Some(module) = entry.module else {
                continue;
            };
            let module_facts = modules.entry(module).or_default();
            for surface in entry.surfaces {
                diagnostics.absorb(surface.diagnostics);
                module_facts.insert(surface.types, surface.members, &mut diagnostics);
            }
        }

        if record_limit_hit {
            diagnostics.warning(
                "limit.records",
                None,
                format!(
                    "producer stopped after {} declaration records",
                    limits.max_records
                ),
            );
        }

        let mut shards = Vec::new();
        let mut emitted_type_ids = HashSet::default();
        let mut emitted_member_ids = HashSet::default();
        let mut emitted_types = HashMap::default();
        let mut emitted_members = HashMap::default();
        for (module, facts) in modules {
            let mut types = Vec::new();
            let mut selected_type_ids = HashSet::default();
            for (id, fact) in facts.types {
                if let Some(existing) = emitted_types.get(&id) {
                    if !equivalent_type_fact(existing, &fact) {
                        diagnostics.warning(
                            "jdk.jmod.conflicting_type",
                            Some(module.clone()),
                            "duplicate JDK declarations disagree; retained the lexically first module",
                        );
                    }
                    continue;
                }
                if emitted_type_ids.insert(id.clone()) {
                    emitted_types.insert(id.clone(), fact.clone());
                    selected_type_ids.insert(id);
                    types.push(fact);
                }
            }
            let mut members = Vec::new();
            for (id, fact) in facts.members {
                if !selected_type_ids.contains(&fact.owner) {
                    continue;
                }
                if let Some(existing) = emitted_members.get(&id) {
                    if !equivalent_member_fact(existing, &fact) {
                        diagnostics.warning(
                            "jdk.jmod.conflicting_member",
                            Some(module.clone()),
                            "duplicate JDK members disagree; retained the lexically first module",
                        );
                    }
                    continue;
                }
                if emitted_member_ids.insert(id.clone()) {
                    emitted_members.insert(id, fact.clone());
                    members.push(fact);
                }
            }
            if types.is_empty() {
                continue;
            }
            types.sort_unstable_by(|left: &TypeFact, right: &TypeFact| left.id.cmp(&right.id));
            members
                .sort_unstable_by(|left: &MemberFact, right: &MemberFact| left.id.cmp(&right.id));
            shards.push(AuthoredShard {
                id: format!("declarations.jdk.{module}"),
                activation: activation_for(request, artifact.sha256()),
                payload: AuthoredPayload::DeclarationFacts {
                    types,
                    members,
                    relations: Vec::new(),
                },
                runtime_values: None,
                runtime_contracts: None,
                collection_flows: None,
                deferred_yields: None,
                conditional_type_refinements: None,
            });
        }

        if shards.is_empty() {
            diagnostics.error(
                "jdk.jmod.no_external_declarations",
                None,
                "JDK JMOD source set contains no externally visible Java declarations",
            );
            return failed_with_diagnostics(artifact.sha256(), diagnostics);
        }
        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        let completeness = if diagnostics.is_empty() && suppressed_diagnostics.total() == 0 {
            Completeness::Complete
        } else {
            Completeness::Partial
        };
        ArtifactProduction {
            artifact_sha256: Some(artifact.sha256().to_owned()),
            pack: Some(AuthoredSemanticModelPack {
                schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: request.pack_id.clone(),
                version: request.pack_version.clone(),
                producer: Producer {
                    name: "bifrost-jdk-jmods".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                language: "java".to_owned(),
                ecosystem: request.ecosystem.clone(),
                compatibility: request.compatibility.clone(),
                provenance: request.provenance.clone(),
                license: request.license.clone(),
                completeness,
                safety: request.safety.clone(),
                carried_sources: Vec::new(),
                cpp_portability: None,
                shards,
            }),
            completeness,
            diagnostics,
            suppressed_diagnostics,
        }
    }
}

/// One module archive after its classes have been read and parsed.
///
/// The parse is done but the facts are not inserted yet: insertion order is an
/// artifact-level decision, so the assembly inserts them once every module has
/// been read.
struct LoadedJmod {
    /// The module the source entry names, or `None` when the producer rejected
    /// the entry as a module archive and reported that itself.
    module: Option<String>,
    /// What reading the archive and parsing its class surfaces reported, in the
    /// order a single pass reports it.
    read_diagnostics: Vec<ProducerDiagnostic>,
    /// One entry per retained class surface, in class-entry order.
    surfaces: Vec<LoadedJmodSurface>,
    /// Declaration records the parse took from its budget.
    records_used: usize,
    /// Whether the parse stopped because its budget was empty.
    record_limit_hit: bool,
}

/// The facts of one retained class surface, and what producing them reported.
struct LoadedJmodSurface {
    types: Vec<TypeFact>,
    members: Vec<MemberFact>,
    diagnostics: Vec<ProducerDiagnostic>,
}

/// The declaration-record budget the parse spends.
///
/// One budget is spent across an artifact's modules, so an artifact that
/// demands more records than the limit retains exactly the records a single
/// pass in source-entry order would have retained.
struct RecordBudget {
    remaining: usize,
    exhausted: bool,
}

impl RecordBudget {
    fn new(limits: &ArtifactProducerLimits) -> Self {
        Self {
            remaining: limits.max_records,
            exhausted: false,
        }
    }
}

/// Whether these modules can only be assembled into the bytes of a single pass
/// that shares one record budget across the whole artifact.
///
/// Every module was parsed under a budget of its own, and the two agree unless
/// the shared budget would have run out: inside the module whose demand
/// exceeds what the single pass would still have had, or at any later module,
/// which the single pass would have stopped at. A module that demanded more
/// than a whole budget reports that itself.
fn loaded_demands_shared_budget(loaded: &[LoadedJmod], limits: &ArtifactProducerLimits) -> bool {
    let mut consumed = 0usize;
    loaded.iter().any(|entry| {
        consumed += entry.records_used;
        entry.record_limit_hit || consumed > limits.max_records
    })
}

/// A loaded module that contributes diagnostics and no retained class surface.
///
/// The source entry did not name a module archive, the archive could not be
/// read, or it carries no module descriptor. In every case the module
/// contributes nothing to the pack, and a declaration record it never produced
/// is never charged to the budget.
fn loaded_without_surfaces(
    module: Option<String>,
    mut diagnostics: BoundedProducerDiagnostics,
    records_before: usize,
    budget: &RecordBudget,
) -> LoadedJmod {
    LoadedJmod {
        module,
        read_diagnostics: diagnostics.take_retained(),
        surfaces: Vec::new(),
        records_used: records_before - budget.remaining,
        record_limit_hit: budget.exhausted,
    }
}

/// Read one module archive and parse every class surface it declares.
///
/// The caller supplies the record budget the parse spends from: the parallel
/// load gives each module a budget of its own and the single pass shares one
/// across the artifact. `None` means the production was cancelled.
fn load_jmod_entry(
    source_entry: &ExactSourceEntry,
    limits: &ArtifactProducerLimits,
    cancellation: Option<&CancellationToken>,
    budget: &mut RecordBudget,
) -> Option<LoadedJmod> {
    let records_before = budget.remaining;
    let mut diagnostics = BoundedProducerDiagnostics::unbounded(limits);
    let relative_path = source_entry.relative_path();
    let Some(module) = jmod_module_name(relative_path, &mut diagnostics) else {
        return Some(loaded_without_surfaces(
            None,
            diagnostics,
            records_before,
            budget,
        ));
    };
    let bytes = source_entry.bytes();
    if zip_directory_status_with_limits(
        bytes,
        MAX_JMOD_ARCHIVE_ENTRIES,
        MAX_JMOD_CENTRAL_DIRECTORY_BYTES,
    ) == super::java_artifact::ZipDirectoryStatus::Exceeded
    {
        diagnostics.error(
            "limit.archive_directory",
            Some(relative_path.to_owned()),
            "JDK JMOD central directory exceeds bounded entry or byte limits",
        );
        return Some(loaded_without_surfaces(
            Some(module),
            diagnostics,
            records_before,
            budget,
        ));
    }
    let mut archive = match ZipArchive::new(Cursor::new(bytes)) {
        Ok(archive) => archive,
        Err(_) => {
            diagnostics.error(
                "jdk.jmod.invalid",
                Some(relative_path.to_owned()),
                "JDK JMOD is not a readable ZIP archive",
            );
            return Some(loaded_without_surfaces(
                Some(module),
                diagnostics,
                records_before,
                budget,
            ));
        }
    };
    let entry_limit = archive.len().min(MAX_JMOD_ARCHIVE_ENTRIES);
    if archive.len() > MAX_JMOD_ARCHIVE_ENTRIES {
        diagnostics.warning(
            "limit.archive_entries",
            Some(relative_path.to_owned()),
            format!("producer inspected at most {MAX_JMOD_ARCHIVE_ENTRIES} JMOD archive entries"),
        );
    }
    let mut total_class_bytes = 0u64;
    let mut class_entries = Vec::new();
    let mut module_info = None;
    for index in 0..entry_limit {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return None;
        }
        let Ok(mut entry) = archive.by_index(index) else {
            diagnostics.warning(
                "jdk.jmod.entry",
                Some(relative_path.to_owned()),
                format!("could not read JMOD entry at index {index}"),
            );
            continue;
        };
        let entry_name = entry.name().to_owned();
        if entry_name == "classes/module-info.class" {
            let mut bytes = Vec::new();
            if entry
                .by_ref()
                .take(MAX_JMOD_CLASS_ENTRY_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)
                .is_err()
                || bytes.len() as u64 > MAX_JMOD_CLASS_ENTRY_BYTES
            {
                diagnostics.error(
                    "jdk.jmod.module_info",
                    Some(format!("{relative_path}:{entry_name}")),
                    "could not read bounded module-info.class bytes",
                );
            } else {
                module_info = Some(bytes);
            }
            continue;
        }
        let class_entry = match jmod_class_entry(&entry_name, &mut diagnostics, relative_path) {
            Some(entry) => entry,
            None => continue,
        };
        let next_total = total_class_bytes.saturating_add(entry.size());
        if entry.size() > MAX_JMOD_CLASS_ENTRY_BYTES || next_total > MAX_JMOD_TOTAL_CLASS_BYTES {
            diagnostics.warning(
                "limit.archive_bytes",
                Some(format!("{relative_path}:{class_entry}")),
                "JMOD class entry exceeded the bounded extraction budget",
            );
            continue;
        }
        total_class_bytes = next_total;
        let mut class_bytes = Vec::with_capacity(entry.size() as usize);
        if entry
            .by_ref()
            .take(MAX_JMOD_CLASS_ENTRY_BYTES.saturating_add(1))
            .read_to_end(&mut class_bytes)
            .is_err()
            || class_bytes.len() as u64 > MAX_JMOD_CLASS_ENTRY_BYTES
        {
            diagnostics.warning(
                "jdk.jmod.entry_read",
                Some(format!("{relative_path}:{class_entry}")),
                "could not read bounded JMOD class entry bytes",
            );
            continue;
        }
        class_entries.push((class_entry, class_bytes));
    }
    class_entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let exported_packages = match module_info
        .as_deref()
        .and_then(|bytes| parse_module_exports(bytes).ok())
    {
        Some(packages) => packages,
        None => {
            diagnostics.error(
                "jdk.jmod.module_info",
                Some(relative_path.to_owned()),
                "JDK JMOD is missing a structurally valid module-info.class descriptor",
            );
            return Some(loaded_without_surfaces(
                Some(module),
                diagnostics,
                records_before,
                budget,
            ));
        }
    };
    // The surfaces are parsed here but their facts are handed to the caller,
    // which inserts them in source-entry order.
    let read_diagnostics = diagnostics.take_retained();
    let mut surfaces = Vec::new();
    let mut parsed = Vec::new();
    for (class_entry, class_bytes) in class_entries {
        let surface = match class_surface(
            relative_path,
            &class_entry,
            &class_bytes,
            limits.max_signature_depth,
            &mut budget.remaining,
            &mut budget.exhausted,
            &mut diagnostics,
        ) {
            JavaClassSurfaceOutcome::Declared(surface) => surface,
            JavaClassSurfaceOutcome::Excluded | JavaClassSurfaceOutcome::Skipped => continue,
            JavaClassSurfaceOutcome::Invalid => {
                diagnostics.warning(
                    "java.class.invalid",
                    Some(format!("{relative_path}:{class_entry}")),
                    "JMOD class entry did not contain supported bounded metadata",
                );
                continue;
            }
        };
        parsed.push(surface);
    }
    let visibility_by_name = parsed
        .iter()
        .map(|surface| (surface.name.clone(), surface.visibility))
        .collect::<HashMap<_, _>>();
    for mut surface in parsed {
        let mut effective = surface.visibility;
        let mut enclosing = surface.name.as_str();
        while let Some((owner, _)) = enclosing.rsplit_once('.') {
            if let Some(owner_visibility) = visibility_by_name.get(owner) {
                effective = restrict_visibility(effective, *owner_visibility);
            }
            enclosing = owner;
        }
        if !matches!(effective, Visibility::Public | Visibility::Protected)
            || !exported_packages.contains(&surface.package_name)
        {
            continue;
        }
        surface.visibility = effective;
        let (types, members) = class_surface_facts(surface, limits.max_records, &mut diagnostics);
        surfaces.push(LoadedJmodSurface {
            types,
            members,
            diagnostics: diagnostics.take_retained(),
        });
    }
    // Every diagnostic this entry reported has to reach the assembly.
    debug_assert!(diagnostics.is_empty());
    Some(LoadedJmod {
        module: Some(module),
        read_diagnostics,
        surfaces,
        records_used: records_before - budget.remaining,
        record_limit_hit: budget.exhausted,
    })
}

fn restrict_visibility(declared: Visibility, enclosing: Visibility) -> Visibility {
    match (declared, enclosing) {
        (Visibility::Private, _) | (_, Visibility::Private) => Visibility::Private,
        (Visibility::Package, _) | (_, Visibility::Package) => Visibility::Package,
        (Visibility::Protected, _) | (_, Visibility::Protected) => Visibility::Protected,
        _ => Visibility::Public,
    }
}

#[derive(Clone, Copy)]
enum Constant<'a> {
    Utf8(&'a str),
    Class,
    Package(u16),
    Other,
}

struct ClassReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ClassReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], ()> {
        let end = self.position.checked_add(length).ok_or(())?;
        let result = self.bytes.get(self.position..end).ok_or(())?;
        self.position = end;
        Ok(result)
    }
    fn u8(&mut self) -> Result<u8, ()> {
        Ok(*self.take(1)?.first().ok_or(())?)
    }
    fn u16(&mut self) -> Result<u16, ()> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    fn u32(&mut self) -> Result<u32, ()> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    fn skip(&mut self, length: usize) -> Result<(), ()> {
        self.take(length).map(|_| ())
    }
}

fn parse_module_exports(bytes: &[u8]) -> Result<HashSet<String>, ()> {
    let mut reader = ClassReader::new(bytes);
    if reader.u32()? != 0xCAFEBABE {
        return Err(());
    }
    reader.u16()?;
    reader.u16()?;
    let constant_count = reader.u16()? as usize;
    let mut constants = vec![Constant::Other; constant_count];
    let mut index = 1;
    while index < constant_count {
        constants[index] = match reader.u8()? {
            1 => {
                let length = reader.u16()? as usize;
                let text = std::str::from_utf8(reader.take(length)?).map_err(|_| ())?;
                Constant::Utf8(text)
            }
            7 => {
                reader.u16()?;
                Constant::Class
            }
            20 => Constant::Package(reader.u16()?),
            3 | 4 => {
                reader.skip(4)?;
                Constant::Other
            }
            5 | 6 => {
                reader.skip(8)?;
                index += 1;
                Constant::Other
            }
            8 | 16 | 19 => {
                reader.skip(2)?;
                Constant::Other
            }
            9 | 10 | 11 | 12 | 17 | 18 => {
                reader.skip(4)?;
                Constant::Other
            }
            15 => {
                reader.skip(3)?;
                Constant::Other
            }
            _ => return Err(()),
        };
        index += 1;
    }
    let access = reader.u16()?;
    if access & 0x8000 == 0 {
        return Err(());
    }
    reader.u16()?;
    reader.u16()?;
    skip_table(&mut reader, 2)?;
    skip_members(&mut reader)?;
    skip_members(&mut reader)?;
    let attribute_count = reader.u16()? as usize;
    let mut exports = None;
    for _ in 0..attribute_count {
        let name = utf8_constant(&constants, reader.u16()?)?;
        let length = reader.u32()? as usize;
        let attribute = reader.take(length)?;
        if name != "Module" {
            continue;
        }
        let mut module = ClassReader::new(attribute);
        module.u16()?;
        module.u16()?;
        module.u16()?;
        skip_table(&mut module, 6)?;
        let export_count = module.u16()? as usize;
        let mut packages = HashSet::default();
        for _ in 0..export_count {
            let package = package_constant(&constants, module.u16()?)?;
            module.u16()?;
            let targets = module.u16()? as usize;
            module.skip(targets.checked_mul(2).ok_or(())?)?;
            if targets == 0 {
                packages.insert(package.replace('/', "."));
            }
        }
        skip_table(&mut module, 6)?;
        let uses = module.u16()? as usize;
        module.skip(uses.checked_mul(2).ok_or(())?)?;
        let provides = module.u16()? as usize;
        for _ in 0..provides {
            module.u16()?;
            let implementations = module.u16()? as usize;
            module.skip(implementations.checked_mul(2).ok_or(())?)?;
        }
        if module.position != attribute.len() {
            return Err(());
        }
        exports = Some(packages);
    }
    exports.ok_or(())
}

fn skip_table(reader: &mut ClassReader<'_>, width: usize) -> Result<(), ()> {
    let count = reader.u16()? as usize;
    reader.skip(count.checked_mul(width).ok_or(())?)
}

fn skip_members(reader: &mut ClassReader<'_>) -> Result<(), ()> {
    let count = reader.u16()? as usize;
    for _ in 0..count {
        reader.skip(6)?;
        let attributes = reader.u16()? as usize;
        for _ in 0..attributes {
            reader.skip(2)?;
            let length = reader.u32()? as usize;
            reader.skip(length)?;
        }
    }
    Ok(())
}

fn utf8_constant<'a>(constants: &[Constant<'a>], index: u16) -> Result<&'a str, ()> {
    match constants.get(index as usize).copied() {
        Some(Constant::Utf8(text)) => Ok(text),
        _ => Err(()),
    }
}

fn package_constant<'a>(constants: &[Constant<'a>], index: u16) -> Result<&'a str, ()> {
    let Constant::Package(name) = constants.get(index as usize).copied().ok_or(())? else {
        return Err(());
    };
    utf8_constant(constants, name)
}

#[derive(Default)]
struct ModuleFacts {
    types: BTreeMap<String, TypeFact>,
    members: BTreeMap<String, MemberFact>,
}

impl ModuleFacts {
    fn insert(
        &mut self,
        types: Vec<TypeFact>,
        members: Vec<MemberFact>,
        diagnostics: &mut BoundedProducerDiagnostics,
    ) {
        for fact in types {
            if let Some(existing) = self.types.get(&fact.id) {
                if !equivalent_type_fact(existing, &fact) {
                    diagnostics.warning(
                        "jdk.jmod.conflicting_type",
                        Some(fact.name.clone()),
                        "duplicate JDK declarations disagree; retained the lexically first entry",
                    );
                }
            } else {
                self.types.insert(fact.id.clone(), fact);
            }
        }
        for fact in members {
            if let Some(existing) = self.members.get(&fact.id) {
                if !equivalent_member_fact(existing, &fact) {
                    diagnostics.warning(
                        "jdk.jmod.conflicting_member",
                        Some(fact.name.clone()),
                        "duplicate JDK members disagree; retained the lexically first entry",
                    );
                }
            } else {
                self.members.insert(fact.id.clone(), fact);
            }
        }
    }
}

fn equivalent_type_fact(left: &TypeFact, right: &TypeFact) -> bool {
    left.id == right.id
        && left.name == right.name
        && left.type_kind == right.type_kind
        && left.visibility == right.visibility
        && left.is_abstract == right.is_abstract
        && left.is_sealed == right.is_sealed
        && left.has_explicit_type_terms == right.has_explicit_type_terms
        && left.type_parameters == right.type_parameters
        && left.type_parameter_constraints == right.type_parameter_constraints
        && left.underlying_type == right.underlying_type
        && left.embedded_types == right.embedded_types
        && left.hierarchy == right.hierarchy
        && left.aliases == right.aliases
        && left.extension_surfaces == right.extension_surfaces
        && left.guard == right.guard
}

fn equivalent_member_fact(left: &MemberFact, right: &MemberFact) -> bool {
    left.id == right.id
        && left.owner == right.owner
        && left.name == right.name
        && left.member_kind == right.member_kind
        && left.visibility == right.visibility
        && left.is_static == right.is_static
        && left.is_abstract == right.is_abstract
        && left.is_virtual == right.is_virtual
        && left.signature == right.signature
        && left.receiver == right.receiver
        && left.extension_receiver == right.extension_receiver
        && left.extension_receiver_constraints == right.extension_receiver_constraints
        && left.aliases == right.aliases
        && left.guard == right.guard
}

fn activation_for(
    request: &ArtifactProductionRequest,
    sha256: &str,
) -> Vec<crate::analyzer::semantic_model::ActivationSelector> {
    request
        .activation
        .iter()
        .cloned()
        .map(|mut selector| {
            selector.artifact_sha256 = Some(sha256.to_owned());
            selector
        })
        .collect()
}

fn jmod_module_name(
    relative_path: &str,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> Option<String> {
    let components = relative_path.split('/').collect::<Vec<_>>();
    let valid = components.len() == 2
        && components[0] == "jmods"
        && components[1]
            .strip_suffix(".jmod")
            .is_some_and(valid_module_name);
    if valid {
        return components[1].strip_suffix(".jmod").map(str::to_owned);
    }
    diagnostics.error(
        "jdk.jmod.path",
        Some(relative_path.to_owned()),
        "JDK JMOD source-set entries must be jmods/<module>.jmod",
    );
    None
}

fn jmod_class_entry(
    entry_name: &str,
    diagnostics: &mut BoundedProducerDiagnostics,
    relative_path: &str,
) -> Option<String> {
    if !entry_name.starts_with("classes/") {
        if entry_name.starts_with("classes\\") {
            diagnostics.error(
                "jdk.jmod.path",
                Some(format!("{relative_path}:{entry_name}")),
                "JDK JMOD class paths must use forward slashes",
            );
        }
        return None;
    }
    let components = entry_name.split('/').collect::<Vec<_>>();
    if components.len() < 2
        || components
            .iter()
            .any(|component| component.is_empty() || *component == "." || *component == "..")
        || !components
            .last()
            .is_some_and(|name| name.ends_with(".class"))
    {
        diagnostics.error(
            "jdk.jmod.path",
            Some(format!("{relative_path}:{entry_name}")),
            "JDK JMOD class entries must be relative classes/**/*.class paths",
        );
        return None;
    }
    if components
        .last()
        .is_some_and(|name| *name == "module-info.class")
    {
        return None;
    }
    Some(entry_name.to_owned())
}

fn valid_module_name(name: &str) -> bool {
    let mut segment_start = true;
    for character in name.chars() {
        if character == '.' {
            if segment_start {
                return false;
            }
            segment_start = true;
        } else if segment_start {
            if character != '_' && !character.is_ascii_alphabetic() {
                return false;
            }
            segment_start = false;
        } else if character != '_' && !character.is_ascii_alphanumeric() {
            return false;
        }
    }
    !segment_start
}

#[cfg(test)]
pub(crate) fn test_module_info_class_bytes(exports: &[&str]) -> Vec<u8> {
    let constant_count = 6 + exports.len() * 2;
    let mut bytes = Vec::new();
    let put_u16 = |bytes: &mut Vec<u8>, value: u16| bytes.extend(value.to_be_bytes());
    bytes.extend(0xCAFEBABEu32.to_be_bytes());
    put_u16(&mut bytes, 0);
    put_u16(&mut bytes, 53);
    put_u16(&mut bytes, constant_count as u16);
    let utf8 = |bytes: &mut Vec<u8>, text: &str| {
        bytes.push(1);
        put_u16(bytes, text.len() as u16);
        bytes.extend(text.as_bytes());
    };
    utf8(&mut bytes, "module-info");
    bytes.push(7);
    put_u16(&mut bytes, 1);
    utf8(&mut bytes, "java.base");
    bytes.push(19);
    put_u16(&mut bytes, 3);
    utf8(&mut bytes, "Module");
    for (index, package) in exports.iter().enumerate() {
        utf8(&mut bytes, package);
        bytes.push(20);
        put_u16(&mut bytes, (6 + index * 2) as u16);
    }
    bytes.extend(0x8000u16.to_be_bytes());
    put_u16(&mut bytes, 2);
    put_u16(&mut bytes, 0);
    put_u16(&mut bytes, 0);
    put_u16(&mut bytes, 0);
    put_u16(&mut bytes, 0);
    put_u16(&mut bytes, 1);
    put_u16(&mut bytes, 5);
    let attribute_length = 6 + 2 + exports.len() * 6 + 2 + 2 + 2 + 2;
    bytes.extend((attribute_length as u32).to_be_bytes());
    put_u16(&mut bytes, 4);
    put_u16(&mut bytes, 0);
    put_u16(&mut bytes, 0);
    put_u16(&mut bytes, 0);
    put_u16(&mut bytes, exports.len() as u16);
    for (index, _) in exports.iter().enumerate() {
        put_u16(&mut bytes, (7 + index * 2) as u16);
        put_u16(&mut bytes, 0);
        put_u16(&mut bytes, 0);
    }
    put_u16(&mut bytes, 0);
    put_u16(&mut bytes, 0);
    put_u16(&mut bytes, 0);
    put_u16(&mut bytes, 0);
    bytes
}

fn unsupported_direct_production(
    request: &ArtifactProductionRequest,
    limits: &ArtifactProducerLimits,
) -> ArtifactProduction {
    ArtifactProduction::failed(
        ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            source_entry: None,
            code: "artifact.source_set_required".to_owned(),
            location: Some(request.path.to_string_lossy().into_owned()),
            declaration: None,
            message: "JDK JMOD production requires an exact source-set artifact".to_owned(),
        },
        limits,
    )
}

fn cancelled_production(limits: &ArtifactProducerLimits) -> ArtifactProduction {
    ArtifactProduction::failed(
        ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            source_entry: None,
            code: "artifact.cancelled".to_owned(),
            location: None,
            declaration: None,
            message: "JDK JMOD production was cancelled".to_owned(),
        },
        limits,
    )
}

fn failed_with_diagnostics(
    artifact_sha256: &str,
    diagnostics: BoundedProducerDiagnostics,
) -> ArtifactProduction {
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    ArtifactProduction {
        artifact_sha256: Some(artifact_sha256.to_owned()),
        pack: None,
        completeness: Completeness::Partial,
        diagnostics,
        suppressed_diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::jvm::external::{TestClassFile, TestClassMethod, test_class_file_bytes};
    use crate::analyzer::semantic_model::{
        ActivationSelector, Compatibility, CompilerOptions, NameSelector, Provenance, Safety,
        VersionConstraint, compile_pack, read_exact_source_set,
    };
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use zip::write::SimpleFileOptions;

    #[test]
    fn jmod_set_merges_modules_in_sorted_order_and_deduplicates() {
        let root = tempfile::tempdir().unwrap();
        let jmods = root.path().join("jmods");
        fs::create_dir(&jmods).unwrap();
        write_jmod(
            &jmods.join("java.sql.jmod"),
            &[(
                "classes/java/sql/Driver.class",
                test_class_file_bytes(&TestClassFile {
                    internal_name: "java/sql/Driver",
                    super_internal_name: "java/lang/Object",
                    methods: &[TestClassMethod {
                        name: "connect",
                        descriptor: "()V",
                        is_static: false,
                    }],
                    private_nested: false,
                }),
            )],
        );
        let object = test_class_file_bytes(&TestClassFile {
            internal_name: "java/lang/Object",
            super_internal_name: "java/lang/Object",
            methods: &[],
            private_nested: false,
        });
        write_jmod(
            &jmods.join("java.base.jmod"),
            &[
                (
                    "classes/module-info.class",
                    test_module_info_class_bytes(&["java/lang"]),
                ),
                ("classes/java/lang/Object.class", object),
            ],
        );
        let relative_paths = vec![
            PathBuf::from("jmods/java.sql.jmod"),
            PathBuf::from("jmods/java.base.jmod"),
        ];
        let artifact = read_exact_source_set(
            root.path(),
            &relative_paths,
            16,
            8,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let production = JdkJmodSetPackProducer.produce_loaded_artifact(
            &request(root.path()),
            &ArtifactProducerLimits::default(),
            None,
            &artifact,
        );
        assert_eq!(production.completeness, Completeness::Complete);
        assert!(
            production.diagnostics.is_empty(),
            "{:?}",
            production.diagnostics
        );
        let pack = production.pack.expect("JMOD pack");
        compile_pack(&pack, &CompilerOptions::default()).unwrap();
        assert!(pack.carried_sources.is_empty());
        assert_eq!(
            pack.shards
                .iter()
                .map(|shard| shard.id.as_str())
                .collect::<Vec<_>>(),
            vec!["declarations.jdk.java.base", "declarations.jdk.java.sql"]
        );
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &pack.shards[0].payload
        else {
            panic!("JMOD producer must emit declaration facts")
        };
        assert!(types.iter().any(|fact| fact.name == "java.lang.Object"));
        assert!(members.is_empty());
        assert!(matches!(
            types[0].locator,
            crate::analyzer::semantic_model::Locator::Artifact { .. }
        ));
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &pack.shards[1].payload
        else {
            panic!("JMOD producer must emit declaration facts")
        };
        assert!(types.iter().any(|fact| fact.name == "java.sql.Driver"));
        assert!(members.iter().any(|fact| fact.name == "connect"));
        assert!(
            members
                .iter()
                .find(|fact| fact.name == "connect")
                .is_some_and(|fact| fact.callable_family_complete)
        );
    }

    #[test]
    fn malformed_jmod_keeps_valid_module_but_reports_partial_completeness() {
        let root = tempfile::tempdir().unwrap();
        let jmods = root.path().join("jmods");
        fs::create_dir(&jmods).unwrap();
        fs::write(jmods.join("bad.jmod"), b"not a ZIP").unwrap();
        write_jmod(
            &jmods.join("java.base.jmod"),
            &[(
                "classes/java/lang/Object.class",
                test_class_file_bytes(&TestClassFile {
                    internal_name: "java/lang/Object",
                    super_internal_name: "java/lang/Object",
                    methods: &[TestClassMethod {
                        name: "hashCode",
                        descriptor: "()I",
                        is_static: false,
                    }],
                    private_nested: false,
                }),
            )],
        );
        let artifact = read_exact_source_set(
            root.path(),
            &[
                PathBuf::from("jmods/bad.jmod"),
                PathBuf::from("jmods/java.base.jmod"),
            ],
            16,
            8,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let production = JdkJmodSetPackProducer.produce_loaded_artifact(
            &request(root.path()),
            &ArtifactProducerLimits::default(),
            None,
            &artifact,
        );
        assert_eq!(production.completeness, Completeness::Partial);
        let pack = production
            .pack
            .expect("the valid module remains inspectable");
        let valid_member = pack
            .shards
            .iter()
            .flat_map(|shard| match &shard.payload {
                AuthoredPayload::DeclarationFacts { members, .. } => members.as_slice(),
                _ => &[],
            })
            .find(|member| member.name == "hashCode")
            .expect("the valid module declaration remains inspectable");
        assert!(valid_member.callable_family_complete);
        assert!(
            production
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "jdk.jmod.invalid" })
        );
    }

    #[test]
    fn oversized_jmod_archive_is_rejected_by_the_exact_source_set_bound() {
        let root = tempfile::tempdir().unwrap();
        let jmods = root.path().join("jmods");
        fs::create_dir(&jmods).unwrap();
        fs::write(jmods.join("java.base.jmod"), vec![0_u8; 128]).unwrap();
        let limits = ArtifactProducerLimits {
            max_artifact_bytes: 64,
            ..ArtifactProducerLimits::default()
        };
        let error = read_exact_source_set(
            root.path(),
            &[PathBuf::from("jmods/java.base.jmod")],
            16,
            8,
            &limits,
        )
        .expect_err("the bounded source-set reader must reject oversized JMOD input");
        assert_eq!(error.code, "limit.artifact_bytes");
    }

    #[test]
    fn jmod_class_paths_use_forward_slashes_across_platforms() {
        let root = tempfile::tempdir().unwrap();
        let jmods = root.path().join("jmods");
        fs::create_dir(&jmods).unwrap();
        let path = jmods.join("java.base.jmod");
        write_jmod(
            &path,
            &[(
                "classes/java/lang/Object.class",
                test_class_file_bytes(&TestClassFile {
                    internal_name: "java/lang/Object",
                    super_internal_name: "java/lang/Object",
                    methods: &[],
                    private_nested: false,
                }),
            )],
        );
        let artifact = read_exact_source_set(
            root.path(),
            &[PathBuf::from("jmods/java.base.jmod")],
            16,
            8,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let production = JdkJmodSetPackProducer.produce_loaded_artifact(
            &request(root.path()),
            &ArtifactProducerLimits::default(),
            None,
            &artifact,
        );
        let pack = production.pack.unwrap();
        let AuthoredPayload::DeclarationFacts { types, .. } = &pack.shards[0].payload else {
            panic!("JMOD producer must emit declaration facts")
        };
        let crate::analyzer::semantic_model::Locator::Artifact { path, symbol } = &types[0].locator
        else {
            panic!("class facts must retain artifact provenance")
        };
        assert_eq!(path, "jmods/java.base.jmod");
        assert_eq!(symbol, "classes/java/lang/Object.class");
    }

    /// The per-module parallel read must assemble exactly the bytes of the
    /// single shared-budget pass, at every record budget where the two can
    /// disagree.
    ///
    /// The single pass is the definition of what this producer produces; the
    /// record budget is the only artifact-wide state the parse touches, so the
    /// budgets around what this fixture demands are where a per-module budget
    /// could retain a declaration the shared budget would have dropped.
    #[test]
    fn parallel_module_reads_reproduce_the_single_pass_pack_at_every_budget() {
        let root = tempfile::tempdir().unwrap();
        let jmods = root.path().join("jmods");
        fs::create_dir(&jmods).unwrap();
        write_jmod(
            &jmods.join("java.base.jmod"),
            &[
                (
                    "classes/java/lang/Object.class",
                    sample_class("java/lang/Object"),
                ),
                (
                    "classes/java/lang/String.class",
                    sample_class("java/lang/String"),
                ),
            ],
        );
        write_jmod(
            &jmods.join("java.logging.jmod"),
            &[(
                "classes/java/util/logging/Logger.class",
                sample_class("java/util/logging/Logger"),
            )],
        );
        write_jmod(
            &jmods.join("java.sql.jmod"),
            &[(
                "classes/java/sql/Driver.class",
                sample_class("java/sql/Driver"),
            )],
        );
        let artifact = read_exact_source_set(
            root.path(),
            &[
                PathBuf::from("jmods/java.base.jmod"),
                PathBuf::from("jmods/java.logging.jmod"),
                PathBuf::from("jmods/java.sql.jmod"),
            ],
            16,
            8,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();

        for max_records in [ArtifactProducerLimits::default().max_records, 4, 3, 2, 1] {
            let limits = ArtifactProducerLimits {
                max_records,
                ..ArtifactProducerLimits::default()
            };
            let parallel = JdkJmodSetPackProducer.produce_loaded_artifact(
                &request(root.path()),
                &limits,
                None,
                &artifact,
            );
            let single = JdkJmodSetPackProducer.produce_single_pass(
                &request(root.path()),
                &limits,
                None,
                &artifact,
            );
            assert_eq!(
                parallel.completeness, single.completeness,
                "max_records={max_records}"
            );
            assert_eq!(
                parallel.diagnostics, single.diagnostics,
                "max_records={max_records}"
            );
            let parallel = parallel.pack.expect("parallel pass must emit a pack");
            let single = single.pack.expect("single pass must emit a pack");
            assert_eq!(
                compile_pack(&parallel, &CompilerOptions::default()).unwrap(),
                compile_pack(&single, &CompilerOptions::default()).unwrap(),
                "max_records={max_records}"
            );
        }
    }

    fn sample_class(internal_name: &str) -> Vec<u8> {
        test_class_file_bytes(&TestClassFile {
            internal_name,
            super_internal_name: "java/lang/Object",
            methods: &[TestClassMethod {
                name: "value",
                descriptor: "()Ljava/lang/String;",
                is_static: false,
            }],
            private_nested: false,
        })
    }

    fn request(path: &Path) -> ArtifactProductionRequest {
        ArtifactProductionRequest {
            path: path.to_path_buf(),
            artifact_kind: ExternalArtifactKind::JdkJmodSet,
            pack_id: "jdk-21".to_owned(),
            pack_version: "21.0.8".to_owned(),
            ecosystem: "jdk".to_owned(),
            compatibility: Compatibility {
                bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                toolchains: vec![VersionConstraint {
                    name: "jdk".to_owned(),
                    requirement: "=21.0.8".to_owned(),
                }],
            },
            activation: vec![ActivationSelector {
                package: None,
                module: None,
                toolchain: Some(NameSelector {
                    name: "jdk".to_owned(),
                    version: Some("=21.0.8".to_owned()),
                }),
                targets: vec!["jvm".to_owned()],
                configurations: vec![],
                artifact_sha256: None,
            }],
            provenance: Provenance {
                source: "OpenJDK".to_owned(),
                revision: Some("jdk-21.0.8".to_owned()),
            },
            license: "GPL-2.0-only WITH Classpath-exception-2.0".to_owned(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
        }
    }

    fn write_jmod(path: &Path, entries: &[(&str, Vec<u8>)]) {
        let file = File::create(path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        if !entries
            .iter()
            .any(|(name, _)| *name == "classes/module-info.class")
        {
            let mut packages = entries
                .iter()
                .filter_map(|(name, _)| name.strip_prefix("classes/"))
                .filter_map(|name| name.rsplit_once('/').map(|(package, _)| package))
                .filter(|package| !package.is_empty())
                .collect::<Vec<_>>();
            packages.sort_unstable();
            packages.dedup();
            archive
                .start_file(
                    "classes/module-info.class",
                    SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
                )
                .unwrap();
            archive
                .write_all(&test_module_info_class_bytes(&packages))
                .unwrap();
        }
        for (name, bytes) in entries {
            archive
                .start_file(
                    *name,
                    SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
                )
                .unwrap();
            archive.write_all(bytes).unwrap();
        }
        archive.finish().unwrap();
    }
}
