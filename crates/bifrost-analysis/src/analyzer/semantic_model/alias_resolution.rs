//! Request-local, alias-aware type cursors shared by semantic consumers.
//!
//! Normalization retains typed argument cursors in older environments without
//! an expansion depth bound. Owned applications are rebuilt only by traversing
//! those same scoped cursors; they do not have a second alias expander.

use crate::CancellationToken;
use crate::analyzer::semantic_model::overlay::{
    ModelProvider, ModelProviderSelection, ModelTypeOwnerAnswer, SemanticModelSymbolKind,
    classify_model_type_owner, owner_declaration,
};
use crate::analyzer::semantic_model::{
    ResolvedActiveSemanticModels, SemanticModelOverlay, SemanticModelOverlayBuildError, TypeRef,
};
use crate::hash::{HashMap, HashSet};

/// A consumer's value wrapper. Projection payloads can carry non-type values;
/// ordinary type consumers use TypeRef directly.
pub trait AliasCursorValue: Clone {
    fn type_ref(&self) -> Option<&TypeRef>;
    fn from_type_ref(value: TypeRef) -> Self;
}

impl AliasCursorValue for TypeRef {
    fn type_ref(&self) -> Option<&TypeRef> {
        Some(self)
    }

    fn from_type_ref(value: TypeRef) -> Self {
        value
    }
}

/// A cursor is valid only with the request-local context that created it.
/// Environment and context indices are internal arena handles, never persisted.
#[derive(Clone, Debug)]
pub struct AliasTypeCursor<V> {
    pub value: V,
    pub environment: Option<usize>,
    pub provider: ModelProvider,
    pub alias_context: Option<usize>,
}

impl<V> AliasTypeCursor<V> {
    pub fn new(value: V, provider: ModelProvider) -> Self {
        Self {
            value,
            environment: None,
            provider,
            alias_context: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasExpansionRefusal {
    AliasMissingTarget,
    AliasUnresolvableTarget,
    AliasCycle,
    AliasArityMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasExpansionFailure {
    pub reason: AliasExpansionRefusal,
    pub detail: &'static str,
}

// Immutable snapshots preserve the definition chain of source arguments.
// Member declaration roots start fresh chains; arguments written inside an
// alias definition retain its chain even through a container's Item projection.
struct AliasExpansionFrame {
    parent: Option<usize>,
    identity: (String, String),
}

/// One typed traversal's bindings and active definition chain. Nothing is kept
/// after that traversal. Callers bind nominal arguments to cursors retaining
/// their older environment and definition context, and reset alias_context at
/// fresh member declaration roots. Do not reuse this arena across requests.
pub struct AliasCursorContext<V> {
    pub environments: Vec<HashMap<String, AliasTypeCursor<V>>>,
    frames: Vec<AliasExpansionFrame>,
    stack: Vec<usize>,
    active: HashSet<(String, String)>,
    expanded_alias: bool,
}

impl<V> Default for AliasCursorContext<V> {
    fn default() -> Self {
        Self {
            environments: Vec::new(),
            frames: Vec::new(),
            stack: Vec::new(),
            active: HashSet::default(),
            expanded_alias: false,
        }
    }
}

impl<V> AliasCursorContext<V> {
    /// Begin a new caller traversal step. Reference traversal can retry the
    /// shared expander within this step without forgetting that an alias was
    /// expanded before returning through an older argument environment.
    pub fn begin_normalization(&mut self) {
        self.expanded_alias = !self.stack.is_empty();
    }

    /// Whether this normalization step expanded an alias. This is history,
    /// not proof that the resulting nominal type owns members or drop facts.
    pub fn expanded_alias(&self) -> bool {
        self.expanded_alias
    }

    fn restore(&mut self, context: Option<usize>) {
        if self.stack.last().copied() == context {
            return;
        }
        let mut chain = Vec::new();
        let mut cursor = context;
        let mut common = 0;
        while let Some(index) = cursor {
            // Parents are older arena entries, so the active stack is sorted.
            if let Ok(position) = self.stack.binary_search(&index) {
                common = position + 1;
                break;
            }
            chain.push(index);
            cursor = self.frames[index].parent;
        }
        for index in self.stack.drain(common..) {
            self.active.remove(&self.frames[index].identity);
        }
        for index in chain.into_iter().rev() {
            self.active.insert(self.frames[index].identity.clone());
            self.stack.push(index);
        }
    }
}

/// Follow the same scoped bindings for strict alias heads and application
/// children. Returning through an argument restores its source context; a free
/// source binder is different from an unbound alias-definition parameter.
fn follow_parameter_bindings<V: AliasCursorValue>(
    current: &mut AliasTypeCursor<V>,
    context: &mut AliasCursorContext<V>,
) -> bool {
    let mut followed = false;
    loop {
        context.restore(current.alias_context);
        context.expanded_alias |= current.alias_context.is_some();
        let Some(TypeRef::TypeParameter { name }) = current.value.type_ref() else {
            break;
        };
        let replacement = current
            .environment
            .and_then(|environment| context.environments[environment].get(name))
            .cloned();
        let Some(replacement) = replacement else {
            break;
        };
        *current = replacement;
        followed = true;
    }
    followed
}

/// Follow parameter bindings and selected aliases before a caller
/// classifies a nominal owner. Nominal availability and consumer-specific
/// authority (including primitive/drop classification) remain with the caller.
/// A repeated identity within the active definition chain refuses; returning
/// through a finite argument restores its captured chain, so Id<Id<T>> works.
/// References and non-type wrappers pass through unchanged. The caller owns
/// dereferencing, and calls begin_normalization once per traversal step (not
/// once per reference retry). A refusal terminates the traversal; discard its
/// context. overlay and active must describe one publication. The owner
/// allowlist is untouched. The intrinsic predicate supplies language facts
/// before interpreting a pack's alias encoding; strict endpoint callers use false.
#[allow(clippy::too_many_arguments)]
pub fn normalize_alias_cursor<V: AliasCursorValue>(
    overlay: &SemanticModelOverlay,
    active: &ResolvedActiveSemanticModels,
    language: &str,
    selection: &ModelProviderSelection,
    current: &mut AliasTypeCursor<V>,
    context: &mut AliasCursorContext<V>,
    cancellation: &CancellationToken,
    intrinsic_nominal: impl Fn(&TypeRef) -> bool,
) -> Result<Option<AliasExpansionFailure>, SemanticModelOverlayBuildError> {
    let failure = |reason, detail| Some(AliasExpansionFailure { reason, detail });
    loop {
        if cancellation.is_cancelled() {
            return Err(SemanticModelOverlayBuildError::Cancelled);
        }
        follow_parameter_bindings(current, context);
        let Some(ty @ (TypeRef::Named { .. } | TypeRef::Declared { .. })) =
            current.value.type_ref()
        else {
            // A lexical parameter restored from a source argument is known
            // independently of this alias definition. An unbound parameter
            // still in the definition context has no such authority.
            if context.expanded_alias
                && (matches!(current.value.type_ref(), Some(TypeRef::Unknown))
                    || (matches!(
                        current.value.type_ref(),
                        Some(TypeRef::TypeParameter { .. })
                    ) && current.alias_context.is_some()))
            {
                return Ok(failure(
                    AliasExpansionRefusal::AliasUnresolvableTarget,
                    "the alias target does not establish a bound type",
                ));
            }
            return Ok(None);
        };
        // Intrinsic identities are language facts, even when a pack encodes
        // them as target-less aliases. Check after each exact binding/hop,
        // before treating the selected record as a language alias.
        if intrinsic_nominal(ty) {
            return Ok(None);
        }
        let providers = match ty {
            TypeRef::Declared { .. } => ModelProviderSelection::new([current.provider.clone()]),
            _ => selection.clone(),
        };
        let groups = overlay.model_selected_groups(language, ty, &providers, cancellation)?;
        let candidates = groups
            .iter()
            .flatten()
            .filter(|symbol| match ty {
                TypeRef::Named { name, .. } => {
                    symbol.qualified_name == *name || symbol.aliases.contains(name)
                }
                TypeRef::Declared { id, .. } => symbol.id == *id,
                _ => false,
            })
            .collect::<Vec<_>>();
        if candidates
            .iter()
            .any(|symbol| symbol.kind == SemanticModelSymbolKind::TypeAlias)
        {
            // Retain all exact facets: an alias cannot hide a competing owner.
            let ModelTypeOwnerAnswer::Unique {
                declaration: alias, ..
            } = classify_model_type_owner(candidates.iter().copied(), |_| true)
            else {
                return Ok(failure(
                    AliasExpansionRefusal::AliasUnresolvableTarget,
                    "the selected alias declaration is ambiguous",
                ));
            };
            let Some(declaration) = owner_declaration(active, alias) else {
                return Ok(failure(
                    AliasExpansionRefusal::AliasUnresolvableTarget,
                    "the selected alias has no authoritative declaration",
                ));
            };
            let identity = (alias.provenance.pack_digest.clone(), alias.id.clone());
            if !context.active.insert(identity.clone()) {
                return Ok(failure(
                    AliasExpansionRefusal::AliasCycle,
                    "type alias expansion revisited a selected alias identity",
                ));
            }
            let arguments = match ty {
                TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => arguments,
                _ => unreachable!(),
            };
            if declaration.type_parameters.len() != arguments.len() {
                return Ok(failure(
                    AliasExpansionRefusal::AliasArityMismatch,
                    "type alias arguments do not match its declared generic parameters",
                ));
            }
            let Some(target) = &declaration.alias_target else {
                return Ok(failure(
                    AliasExpansionRefusal::AliasMissingTarget,
                    "the selected alias declaration has no target",
                ));
            };
            let environment = context.environments.len();
            context.environments.push(
                declaration
                    .type_parameters
                    .iter()
                    .zip(arguments)
                    .map(|(name, argument)| {
                        (
                            name.clone(),
                            AliasTypeCursor {
                                value: V::from_type_ref(argument.clone()),
                                environment: current.environment,
                                provider: current.provider.clone(),
                                alias_context: current.alias_context,
                            },
                        )
                    })
                    .collect(),
            );
            let frame = context.frames.len();
            context.frames.push(AliasExpansionFrame {
                parent: current.alias_context,
                identity,
            });
            context.stack.push(frame);
            context.expanded_alias = true;
            *current = AliasTypeCursor {
                value: V::from_type_ref(target.clone()),
                environment: Some(environment),
                provider: ModelProvider::from(&alias.provenance),
                alias_context: Some(frame),
            };
            continue;
        }
        return Ok(None);
    }
}

/// Materialize one application for consumers that require owned TypeRefs.
/// Alias expansion and parameter binding still happen only in
/// normalize_alias_cursor; this worklist merely visits and rebuilds children
/// while retaining each cursor's scoped environment and definition context.
/// References and all structural type shapes are preserved, without a depth cap.
/// The language supplies intrinsic nominal authority (such as primitive types);
/// all other nominals written by alias definitions need selected model owners.
pub fn materialize_alias_application(
    overlay: &SemanticModelOverlay,
    active: &ResolvedActiveSemanticModels,
    language: &str,
    current: AliasTypeCursor<TypeRef>,
    intrinsic_nominal: impl Fn(&TypeRef) -> bool,
    cancellation: &CancellationToken,
) -> Result<Result<TypeRef, AliasExpansionFailure>, SemanticModelOverlayBuildError> {
    enum Work {
        Visit(AliasTypeCursor<TypeRef>, bool),
        Assemble(TypeRef, usize),
    }
    let selection = active.model_provider_selection();
    let mut context = AliasCursorContext::default();
    let mut work = vec![Work::Visit(current, false)];
    let mut values = Vec::new();
    while let Some(task) = work.pop() {
        if cancellation.is_cancelled() {
            return Err(SemanticModelOverlayBuildError::Cancelled);
        }
        match task {
            Work::Visit(mut cursor, is_argument) => {
                context.restore(cursor.alias_context);
                context.begin_normalization();
                let followed = follow_parameter_bindings(&mut cursor, &mut context);
                // A known carrier may retain an opaque argument. Only binding
                // resolution can grant this exemption: an alias that expands
                // to Unknown (here or at the root) must still fail below.
                if is_argument
                    && followed
                    && (matches!(cursor.value, TypeRef::Unknown)
                        || (matches!(cursor.value, TypeRef::TypeParameter { .. })
                            && cursor.alias_context.is_none()))
                {
                    values.push(cursor.value);
                    continue;
                }
                if let Some(failure) = normalize_alias_cursor(
                    overlay,
                    active,
                    language,
                    &selection,
                    &mut cursor,
                    &mut context,
                    cancellation,
                    &intrinsic_nominal,
                )? {
                    return Ok(Err(failure));
                }
                // Nominals written by an alias definition need selected
                // authority at every position, not only at the outer owner.
                // Source arguments restore their captured context when bound,
                // so workspace types are not mistaken for broken definitions.
                if cursor.alias_context.is_some()
                    && !intrinsic_nominal(&cursor.value)
                    && matches!(
                        cursor.value,
                        TypeRef::Named { .. } | TypeRef::Declared { .. }
                    )
                {
                    let providers = match &cursor.value {
                        TypeRef::Declared { .. } => {
                            ModelProviderSelection::new([cursor.provider.clone()])
                        }
                        _ => selection.clone(),
                    };
                    if !matches!(
                        overlay.model_type_owner(
                            language,
                            &cursor.value,
                            &providers,
                            cancellation
                        )?,
                        ModelTypeOwnerAnswer::Unique { .. }
                    ) {
                        return Ok(Err(AliasExpansionFailure {
                            reason: AliasExpansionRefusal::AliasUnresolvableTarget,
                            detail: "an alias target nominal has no unique selected type owner",
                        }));
                    }
                }
                let children = application_children_mut(&mut cursor.value)
                    .into_iter()
                    .map(|child| AliasTypeCursor {
                        value: std::mem::replace(child, TypeRef::Unknown),
                        environment: cursor.environment,
                        provider: cursor.provider.clone(),
                        alias_context: cursor.alias_context,
                    })
                    .collect::<Vec<_>>();
                work.push(Work::Assemble(cursor.value, children.len()));
                work.extend(
                    children
                        .into_iter()
                        .rev()
                        .map(|child| Work::Visit(child, true)),
                );
            }
            Work::Assemble(mut value, count) => {
                let children = values.split_off(values.len() - count);
                for (slot, child) in application_children_mut(&mut value)
                    .into_iter()
                    .zip(children)
                {
                    *slot = child;
                }
                values.push(value);
            }
        }
    }
    Ok(Ok(values.pop().expect("one application root")))
}

fn application_children_mut(ty: &mut TypeRef) -> Vec<&mut TypeRef> {
    match ty {
        TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
            arguments.iter_mut().collect()
        }
        TypeRef::Projection {
            owner,
            trait_type,
            arguments,
            ..
        } => {
            let mut children = vec![owner.as_mut()];
            children.extend(trait_type.iter_mut().map(Box::as_mut));
            children.extend(arguments.iter_mut());
            children
        }
        TypeRef::Array { element }
        | TypeRef::ByRef { element, .. }
        | TypeRef::Pointer { element }
        | TypeRef::Slice { element }
        | TypeRef::FixedArray { element, .. }
        | TypeRef::Channel { element, .. } => vec![element.as_mut()],
        TypeRef::Map { key, value } => vec![key.as_mut(), value.as_mut()],
        TypeRef::Wildcard { bound, .. } => bound.iter_mut().map(Box::as_mut).collect(),
        TypeRef::Tuple { elements } => elements.iter_mut().collect(),
        TypeRef::Function { parameters, result } => {
            let mut children = parameters
                .iter_mut()
                .map(|p| &mut p.r#type)
                .collect::<Vec<_>>();
            children.extend(result.iter_mut().map(Box::as_mut));
            children
        }
        TypeRef::Unknown | TypeRef::TypeParameter { .. } => Vec::new(),
    }
}
