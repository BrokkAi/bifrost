//! Immutable composition values retained by the shared store cache.

use super::cache_budget::{RetainedBytes, RetainedHeap};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_semantic::analyzer::semantic_model::overlay::*;
use brokk_bifrost_semantic::analyzer::semantic_model::*;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SemanticModelCompositionDiagnostic {
    pub pack_id: String,
    pub declaration_id: String,
    pub artifact_id: String,
    pub conflicting_artifact_id: Option<String>,
    pub field: &'static str,
}

/// Alias-closure identity: exact language, module/type namespace, and the
/// lexicographically smallest canonical or alias spelling in the closure.
/// Generated owners participate in the same closure as catalog owners.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CompositionGroupKey {
    pub language: String,
    pub module_namespace: bool,
    pub identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepresentativeIdentity {
    pub representative_id: Option<String>,
    /// Owner replacements only; curated member correspondence never renames IDs.
    pub replacements: Vec<(String, String)>,
    pub composed: bool,
    pub disagreement: bool,
}

#[derive(Debug, Clone)]
pub struct ComposedGroup {
    pub symbols: Vec<SemanticModelSymbol>,
    pub source_indices: Vec<usize>,
    pub relations: Vec<(usize, SemanticModelRelation)>,
    pub diagnostics: Vec<SemanticModelCompositionDiagnostic>,
    pub representative: RepresentativeIdentity,
}

/// Valid exactly while the selected active set, ordered shard publication
/// metadata (manifest content identity, descriptor, selectors, source identity,
/// presence, ranks and activation evidence), projected activation provenance
/// (including explanation reason), generated symbols and relations (including
/// non-serialized scope/signature/order fields), and workspace-derived authored
/// Source anchors remain the inputs of this build.
/// Composition reads no analyzer configuration or other workspace rows after
/// these inputs have been captured. This identity is shared by group and
/// discovery entries; eviction can only cause the same questions to be reread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SemanticOverlayBuildIdentity(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ComposedGroupCacheKey {
    pub build: SemanticOverlayBuildIdentity,
    pub selection_digest: Option<[u8; 32]>,
    pub group: CompositionGroupKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CompositionLookup {
    RecordId(String),
    SelectedId { language: String, id: String },
    SelectedName { language: String, name: String },
    OwnerIdentity(CompositionGroupKey),
    Name(String),
    MembersOf(String),
    Uri(String),
    AuthoredPath(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CompositionDiscoveryCacheKey {
    pub build: SemanticOverlayBuildIdentity,
    pub selection_digest: Option<[u8; 32]>,
    pub lookup: CompositionLookup,
}

impl RetainedBytes for ComposedGroupCacheKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self) + group_owned_bytes(&self.group)
    }
}
impl RetainedBytes for CompositionDiscoveryCacheKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self)
            + match &self.lookup {
                CompositionLookup::SelectedId { language, id } => {
                    language.capacity() + id.capacity()
                }
                CompositionLookup::SelectedName { language, name } => {
                    language.capacity() + name.capacity()
                }
                CompositionLookup::OwnerIdentity(key) => group_owned_bytes(key),
                CompositionLookup::RecordId(s)
                | CompositionLookup::Name(s)
                | CompositionLookup::MembersOf(s)
                | CompositionLookup::Uri(s)
                | CompositionLookup::AuthoredPath(s) => s.capacity(),
            }
    }
}
fn group_owned_bytes(key: &CompositionGroupKey) -> usize {
    key.language.capacity() + key.identity.capacity()
}
impl RetainedBytes for Vec<CompositionGroupKey> {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self)
            + self.capacity() * std::mem::size_of::<CompositionGroupKey>()
            + self.iter().map(group_owned_bytes).sum::<usize>()
    }
}
impl RetainedBytes for ComposedGroup {
    fn retained_bytes(&self) -> usize {
        let mut heap = RetainedHeap::default();
        heap.add(std::mem::size_of_val(self));
        heap.vec(&self.symbols);
        heap.vec(&self.source_indices);
        heap.vec(&self.relations);
        heap.vec(&self.diagnostics);
        for symbol in &self.symbols {
            charge_symbol(symbol, &mut heap);
        }
        for (_, relation) in &self.relations {
            for s in [&relation.id, &relation.kind, &relation.from, &relation.to] {
                heap.add(s.capacity());
            }
            if let Some((from, to)) = &relation.pre_composition_endpoints {
                heap.add(from.capacity() + to.capacity());
            }
            charge_provenance(&relation.provenance, &mut heap);
        }
        for d in &self.diagnostics {
            heap.add(d.pack_id.capacity() + d.declaration_id.capacity() + d.artifact_id.capacity());
            heap.add(
                d.conflicting_artifact_id
                    .as_ref()
                    .map_or(0, String::capacity),
            );
        }
        heap.add(
            self.representative
                .representative_id
                .as_ref()
                .map_or(0, String::capacity),
        );
        heap.vec(&self.representative.replacements);
        for (from, to) in &self.representative.replacements {
            heap.add(from.capacity() + to.capacity());
        }
        heap.total()
    }
}

fn charge_strings(values: &Vec<String>, heap: &mut RetainedHeap) {
    heap.vec(values);
    for value in values {
        heap.add(value.capacity());
    }
}
fn charge_provenance(p: &SemanticModelProvenance, heap: &mut RetainedHeap) {
    for s in [
        &p.active_model_set_hash,
        &p.pack_digest,
        &p.pack_id,
        &p.pack_version,
        &p.producer,
        &p.producer_version,
        &p.record_id,
    ] {
        heap.add(s.capacity());
    }
    heap.add(p.rule_id.as_ref().map_or(0, String::capacity));
    if let Some(extraction) = &p.extraction {
        heap.add(match &extraction.inputs {
            ArtifactExtractionInputs::Single { sha256 } => sha256.capacity(),
            ArtifactExtractionInputs::SourceSet { digest } => digest.capacity(),
        });
    }
    let a = &p.activation;
    for s in [&a.status, &a.reason, &a.source_kind, &a.source_id] {
        heap.add(s.capacity());
    }
    let e = &a.matched_evidence;
    heap.add(e.language.capacity() + e.ecosystem.capacity());
    for c in [&e.package, &e.module, &e.toolchain].into_iter().flatten() {
        heap.add(c.name.capacity() + c.version.as_ref().map_or(0, String::capacity));
    }
    for s in [&e.target, &e.configuration, &e.artifact_sha256]
        .into_iter()
        .flatten()
    {
        heap.add(s.capacity());
    }
}
fn charge_symbol(s: &SemanticModelSymbol, heap: &mut RetainedHeap) {
    if let Some(mark) = &s.promoted_from {
        heap.add(mark.declaring_member_id.capacity());
    }
    for v in [&s.id, &s.name, &s.qualified_name, &s.language] {
        heap.add(v.capacity());
    }
    for v in [
        &s.pre_composition_qualified_name,
        &s.owner_id,
        &s.signature,
        &s.callable_shape,
        &s.locator_path,
        &s.locator_symbol,
    ]
    .into_iter()
    .flatten()
    {
        heap.add(v.capacity());
    }
    heap.vec(&s.semantic_contributors);
    for p in &s.semantic_contributors {
        charge_provenance(p, heap);
    }
    charge_provenance(&s.provenance, heap);
    if let Some(scope) = &s.rust_generated_scope {
        heap.add(std::mem::size_of_val(&**scope) + scope.file.capacity() + scope.module.capacity());
    }
    charge_strings(&s.aliases, heap);
    let mut types = Vec::new();
    if let Some(ImplicitOperation::ConversionOperator { target }) = &s.implicit_operation {
        types.push(target);
    }
    heap.vec(&s.exact_return_classes);
    types.extend(&s.exact_return_classes);
    heap.vec(&s.extension_receiver_constraints);
    types.extend(&s.extension_receiver_constraints);
    types.extend(s.value_type.as_ref());
    types.extend(s.proxied_type.as_ref());
    types.extend(s.extension_receiver.as_ref());
    heap.vec(&s.type_parameter_constraints);
    for c in &s.type_parameter_constraints {
        heap.add(c.parameter.capacity() + c.constraint.display.capacity());
        heap.vec(&c.constraint.referenced_types);
        types.extend(&c.constraint.referenced_types);
    }
    if let Some(t) = &s.underlying_type {
        heap.add(t.display.capacity());
        heap.vec(&t.referenced_types);
        types.extend(&t.referenced_types);
    }
    heap.vec(&s.embedded_types);
    types.extend(s.embedded_types.iter().map(|e| &e.target));
    if let Some(TypeCopySemantics::ViaMember { member }) =
        s.value_semantics.as_ref().and_then(|v| v.copy.as_ref())
    {
        heap.add(member.capacity());
    }
    if let Some(signature) = &s.structured_signature {
        charge_strings(&signature.type_parameters, heap);
        charge_parameters(&signature.parameters, heap, &mut types);
        types.extend(signature.returns.as_ref());
    }
    match &s.location {
        SemanticModelLocation::Authored(a) => heap.add(a.path.capacity() + a.symbol.capacity()),
        SemanticModelLocation::Model(m) => heap.add(m.uri.capacity()),
    }
    while let Some(t) = types.pop() {
        match t {
            TypeRef::Unknown => {}
            TypeRef::TypeParameter { name } => heap.add(name.capacity()),
            TypeRef::Named {
                name, arguments, ..
            }
            | TypeRef::Declared {
                id: name,
                arguments,
                ..
            } => {
                heap.add(name.capacity());
                heap.vec(arguments);
                types.extend(arguments);
            }
            TypeRef::Projection {
                owner,
                trait_type,
                name,
                arguments,
            } => {
                heap.add(std::mem::size_of_val(&**owner) + name.capacity());
                types.push(owner);
                if let Some(t) = trait_type {
                    heap.add(std::mem::size_of_val(&**t));
                    types.push(t);
                }
                heap.vec(arguments);
                types.extend(arguments);
            }
            TypeRef::Array { element }
            | TypeRef::ByRef { element, .. }
            | TypeRef::Pointer { element }
            | TypeRef::Slice { element }
            | TypeRef::Channel { element, .. } => {
                heap.add(std::mem::size_of_val(&**element));
                types.push(element);
            }
            TypeRef::FixedArray { element, length } => {
                heap.add(std::mem::size_of_val(&**element) + length.capacity());
                types.push(element);
            }
            TypeRef::Map { key, value } => {
                heap.add(std::mem::size_of_val(&**key) + std::mem::size_of_val(&**value));
                types.extend([&**key, &**value]);
            }
            TypeRef::Wildcard { bound, .. } => {
                if let Some(t) = bound {
                    heap.add(std::mem::size_of_val(&**t));
                    types.push(t);
                }
            }
            TypeRef::Tuple { elements } => {
                heap.vec(elements);
                types.extend(elements);
            }
            TypeRef::Function { parameters, result } => {
                charge_parameters(parameters, heap, &mut types);
                if let Some(t) = result {
                    heap.add(std::mem::size_of_val(&**t));
                    types.push(t);
                }
            }
        }
    }
}
fn charge_parameters<'a>(
    parameters: &'a Vec<Parameter>,
    heap: &mut RetainedHeap,
    types: &mut Vec<&'a TypeRef>,
) {
    heap.vec(parameters);
    for p in parameters {
        heap.add(p.name.as_ref().map_or(0, String::capacity));
        types.push(&p.r#type);
    }
}

pub type SearchCandidate = (
    String,
    Option<String>,
    String,
    String,
    i64,
    i64,
    String,
    String,
    String,
    String,
);

#[derive(Debug)]
pub struct SearchGroup {
    pub key: CompositionGroupKey,
    pub identities: HashSet<String>,
    pub standalone: HashSet<String>,
    pub members: HashSet<String>,
}

impl SearchGroup {
    pub fn spellings(&self) -> impl Iterator<Item = std::borrow::Cow<'_, str>> {
        self.standalone
            .iter()
            .map(|s| std::borrow::Cow::Borrowed(s.as_str()))
            .chain(self.identities.iter().flat_map(|identity| {
                self.members
                    .iter()
                    .map(move |member| std::borrow::Cow::Owned(format!("{identity}.{member}")))
            }))
    }
}

/// Query-independent scalar spellings and their conservative alias closures.
/// Contains no decoded records or record JSON. Products stay factored, and
/// candidate tuples retain the original publication and source-order scalars.
#[derive(Debug)]
pub struct SearchCandidateStream {
    pub candidates: Vec<SearchCandidate>,
    pub groups: Vec<SearchGroup>,
    pub seeds_by_group: Vec<Vec<(String, String)>>,
    /// The sole owner's pack digest, or None for multiple/generated facets.
    pub single_contributors: Vec<Option<String>>,
    /// Some(name) is the unique, unguarded raw owner. None requires the shared
    /// ranked/guarded qualification read, without composing its group.
    pub owner_qualifications: HashMap<String, Option<String>>,
    pub orphans: Vec<((String, String), Vec<String>)>,
}
impl RetainedBytes for SemanticOverlayBuildIdentity {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self)
    }
}
impl RetainedBytes for SearchCandidateStream {
    fn retained_bytes(&self) -> usize {
        let mut heap = RetainedHeap::default();
        heap.add(std::mem::size_of_val(self));
        heap.vec(&self.candidates);
        for c in &self.candidates {
            for s in [&c.0, &c.2, &c.3, &c.6, &c.7, &c.8, &c.9] {
                heap.add(s.capacity());
            }
            heap.add(c.1.as_ref().map_or(0, String::capacity));
        }
        heap.vec(&self.groups);
        for group in &self.groups {
            heap.add(group_owned_bytes(&group.key));
            for set in [&group.identities, &group.standalone, &group.members] {
                heap.hash_set(set);
                for s in set {
                    heap.add(s.capacity());
                }
            }
        }
        heap.vec(&self.seeds_by_group);
        for seeds in &self.seeds_by_group {
            heap.vec(seeds);
            for (language, owner) in seeds {
                heap.add(language.capacity() + owner.capacity());
            }
        }
        heap.vec(&self.single_contributors);
        for digest in self.single_contributors.iter().flatten() {
            heap.add(digest.capacity());
        }
        heap.map(&self.owner_qualifications);
        for (id, name) in &self.owner_qualifications {
            heap.add(id.capacity() + name.as_ref().map_or(0, String::capacity));
        }
        heap.vec(&self.orphans);
        for ((language, owner), spellings) in &self.orphans {
            heap.add(language.capacity() + owner.capacity());
            heap.vec(spellings);
            for s in spellings {
                heap.add(s.capacity());
            }
        }
        heap.total()
    }
}
