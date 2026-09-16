//! Immutable algebra values for compositional name resolution.

use std::fmt;
use std::hash::Hash;

use brokk_bifrost_core::analyzer::canonical_hash::{
    CanonicalHasher, hash_domain_bytes, write_lower_hex,
};

use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BoundaryStatus, CandidateOutcome, PrecedenceTier, ResolutionCompletionKind,
    ResolutionCompletionReasonKind, ResolutionWitnessKind,
};

use super::completion_reasons::CompletionReasons;
use super::never_cancelled;

macro_rules! digest_id {
    ($name:ident, $domain:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn from_digest(digest: [u8; 32]) -> Self {
                Self(digest)
            }

            pub fn hash_bytes(bytes: impl AsRef<[u8]>) -> Self {
                Self(hash_domain_bytes($domain, bytes.as_ref()))
            }

            pub const fn as_bytes(self) -> [u8; 32] {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_lower_hex(&self.0, formatter)
            }
        }
    };
}

digest_id!(BindingFragmentId, b"bifrost-resolution-fragment:v1");
digest_id!(BindingNodeId, b"bifrost-resolution-node:v1");
digest_id!(PartialPathId, b"bifrost-resolution-partial-path:v1");
digest_id!(SemanticId, b"bifrost-resolution-semantic:v1");
digest_id!(StackVariableId, b"bifrost-resolution-stack-variable:v1");
digest_id!(AlphaRenamingId, b"bifrost-resolution-alpha-renaming:v1");

pub type StackVariable = StackVariableId;

impl BindingNodeId {
    /// The canonical key for the one mount-independent root boundary.
    pub(crate) const UNIVERSAL_ROOT_BOUNDARY_KEY: i64 = 0;

    /// The one mount-independent root boundary shared by every selected
    /// resolution fragment.
    ///
    /// Persistent interiors refer to this node through boundary key zero. It
    /// is deliberately outside every fragment-local identity space so equal
    /// content mounted at different workspace paths still meets at the same
    /// universal boundary.
    pub(crate) fn universal_root() -> Self {
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-boundary-node:v1");
        hasher.field(
            "boundary_key",
            &Self::UNIVERSAL_ROOT_BOUNDARY_KEY.to_be_bytes(),
        );
        Self::from_digest(hasher.finish())
    }

    /// Derive a node identity from its fragment and producer-stable local key.
    pub fn in_fragment(fragment: BindingFragmentId, local_key: &[u8]) -> Self {
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-node-in-fragment:v1");
        hasher.field("fragment", &fragment.as_bytes());
        hasher.field("local_key", local_key);
        Self::from_digest(hasher.finish())
    }
}

impl PartialPathId {
    /// Derive a globally unique transition identity from its owning fragment
    /// and a producer-stable local key. The cycle certifier intentionally sees
    /// only this value, so fragment identity must be part of the digest.
    pub fn in_fragment(fragment: BindingFragmentId, local_key: &[u8]) -> Self {
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-path-in-fragment:v1");
        hasher.field("fragment", &fragment.as_bytes());
        hasher.field("local_key", local_key);
        Self::from_digest(hasher.finish())
    }
}

impl SemanticId {
    /// Derive a semantic identity from its fragment and producer-stable local
    /// key. Shared lookup and intrinsic identities deliberately do not use
    /// this constructor.
    pub fn in_fragment(fragment: BindingFragmentId, local_key: &[u8]) -> Self {
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-semantic-in-fragment:v1");
        hasher.field("fragment", &fragment.as_bytes());
        hasher.field("local_key", local_key);
        Self::from_digest(hasher.finish())
    }
}

impl StackVariableId {
    /// Derive a stack-variable identity from its fragment and a
    /// producer-stable local key.
    pub fn in_fragment(fragment: BindingFragmentId, local_key: &[u8]) -> Self {
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-stack-variable-in-fragment:v1");
        hasher.field("fragment", &fragment.as_bytes());
        hasher.field("local_key", local_key);
        Self::from_digest(hasher.finish())
    }

    /// Mint a fresh alpha-equivalent identity for one use of a partial path.
    pub fn alpha_renamed(self, renaming: AlphaRenamingId) -> Self {
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-renamed-variable:v1");
        hasher.field("variable", &self.as_bytes());
        hasher.field("renaming", &renaming.as_bytes());
        Self::from_digest(hasher.finish())
    }
}

/// The stack effect or semantic endpoint represented by one graph node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingNodeKind {
    Root,
    Scope,
    PushSymbol(SemanticId),
    PopSymbol(SemanticId),
    /// Push a symbol together with the scope stack at traversal time.
    PushScopedSymbol(SemanticId),
    PopScopedSymbol(SemanticId),
    DropScopes,
    JumpToScope(BindingNodeId),
    Reference(SemanticId),
    Definition(SemanticId),
}

/// A top-first fixed stack prefix followed by an optional remainder variable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StackPattern<T> {
    fixed: Box<[T]>,
    tail: Option<StackVariableId>,
}

impl<T> StackPattern<T> {
    pub fn new(fixed: impl Into<Box<[T]>>, tail: Option<StackVariableId>) -> Self {
        Self {
            fixed: fixed.into(),
            tail,
        }
    }

    pub fn closed(fixed: impl Into<Box<[T]>>) -> Self {
        Self::new(fixed, None)
    }

    pub fn open(fixed: impl Into<Box<[T]>>, tail: StackVariableId) -> Self {
        Self::new(fixed, Some(tail))
    }

    pub fn fixed(&self) -> &[T] {
        &self.fixed
    }

    pub const fn tail(&self) -> Option<StackVariableId> {
        self.tail
    }
}

/// One symbol-stack cell. Scoped symbols carry the partial scope stack that
/// was current when the symbol was pushed.
///
/// Keeping the attached scopes in the algebra is essential: two occurrences
/// of the same textual symbol are not interchangeable when they close over
/// different lexical scopes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PartialScopedSymbol {
    symbol: SemanticId,
    scopes: Option<StackPattern<BindingNodeId>>,
}

impl PartialScopedSymbol {
    pub const fn unscoped(symbol: SemanticId) -> Self {
        Self {
            symbol,
            scopes: None,
        }
    }

    pub fn scoped(symbol: SemanticId, scopes: StackPattern<BindingNodeId>) -> Self {
        Self {
            symbol,
            scopes: Some(scopes),
        }
    }

    pub const fn symbol(&self) -> SemanticId {
        self.symbol
    }

    pub fn scopes(&self) -> Option<&StackPattern<BindingNodeId>> {
        self.scopes.as_ref()
    }
}

pub type SymbolStackPattern = StackPattern<PartialScopedSymbol>;
pub type ScopeStackPattern = StackPattern<BindingNodeId>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackUnificationError {
    FixedCellMismatch { index: usize },
    ClosedStackLengthMismatch,
    RecursiveVariableBinding(StackVariableId),
}

impl fmt::Display for StackUnificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FixedCellMismatch { index } => {
                write!(formatter, "stack cells differ at index {index}")
            }
            Self::ClosedStackLengthMismatch => {
                formatter.write_str("a closed stack cannot absorb the remaining cells")
            }
            Self::RecursiveVariableBinding(variable) => {
                write!(formatter, "stack variable {variable} would contain itself")
            }
        }
    }
}

impl std::error::Error for StackUnificationError {}

/// One finite substitution produced by unifying stack patterns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSubstitution<T> {
    bindings: HashMap<StackVariableId, StackPattern<T>>,
}

impl<T> Default for StackSubstitution<T> {
    fn default() -> Self {
        Self {
            bindings: HashMap::default(),
        }
    }
}

impl<T> StackSubstitution<T> {
    pub fn binding(&self, variable: StackVariableId) -> Option<&StackPattern<T>> {
        self.bindings.get(&variable)
    }
}

impl<T: Clone + Eq> StackSubstitution<T> {
    /// Add one equality to an existing substitution. Applying existing
    /// bindings first is what makes repeated occurrences of a tail variable
    /// constrain, rather than overwrite, its earlier binding.
    fn unify_patterns_with_poll<P, C>(
        &mut self,
        left: &StackPattern<T>,
        right: &StackPattern<T>,
        clone_cell: &mut C,
        cancelled: &mut P,
    ) -> Option<Result<(), StackUnificationError>>
    where
        P: FnMut() -> bool,
        C: FnMut(&T, &mut P) -> Option<T>,
    {
        let left = match self.apply_with_poll(left, clone_cell, cancelled)? {
            Ok(left) => left,
            Err(error) => return Some(Err(error)),
        };
        let right = match self.apply_with_poll(right, clone_cell, cancelled)? {
            Ok(right) => right,
            Err(error) => return Some(Err(error)),
        };
        let shared = left.fixed.len().min(right.fixed.len());
        for index in 0..shared {
            if cancelled() {
                return None;
            }
            if left.fixed[index] != right.fixed[index] {
                return Some(Err(StackUnificationError::FixedCellMismatch { index }));
            }
        }

        let left_remainder = &left.fixed[shared..];
        let right_remainder = &right.fixed[shared..];
        debug_assert!(left_remainder.is_empty() || right_remainder.is_empty());

        match (left_remainder.is_empty(), right_remainder.is_empty()) {
            (true, true) => match (left.tail, right.tail) {
                (None, None) => {}
                (Some(variable), None) | (None, Some(variable)) => {
                    if let Err(error) = self.bind(variable, StackPattern::closed(Vec::new())) {
                        return Some(Err(error));
                    }
                }
                (Some(left_variable), Some(right_variable)) if left_variable != right_variable => {
                    if let Err(error) = self.bind(
                        left_variable,
                        StackPattern::open(Vec::new(), right_variable),
                    ) {
                        return Some(Err(error));
                    }
                }
                (Some(_), Some(_)) => {}
            },
            (true, false) => {
                let Some(variable) = left.tail else {
                    return Some(Err(StackUnificationError::ClosedStackLengthMismatch));
                };
                let fixed = clone_cells_with_poll(right_remainder, clone_cell, cancelled)?;
                if let Err(error) = self.bind(variable, StackPattern::new(fixed, right.tail)) {
                    return Some(Err(error));
                }
            }
            (false, true) => {
                let Some(variable) = right.tail else {
                    return Some(Err(StackUnificationError::ClosedStackLengthMismatch));
                };
                let fixed = clone_cells_with_poll(left_remainder, clone_cell, cancelled)?;
                if let Err(error) = self.bind(variable, StackPattern::new(fixed, left.tail)) {
                    return Some(Err(error));
                }
            }
            (false, false) => unreachable!("one fixed prefix must end first"),
        }
        Some(Ok(()))
    }
}

impl<T: Clone> StackSubstitution<T> {
    fn bind(
        &mut self,
        variable: StackVariableId,
        pattern: StackPattern<T>,
    ) -> Result<(), StackUnificationError> {
        if pattern.tail == Some(variable) {
            if pattern.fixed.is_empty() {
                return Ok(());
            }
            return Err(StackUnificationError::RecursiveVariableBinding(variable));
        }
        self.bindings.insert(variable, pattern);
        Ok(())
    }

    fn apply_with_poll<P, C>(
        &self,
        pattern: &StackPattern<T>,
        clone_cell: &mut C,
        cancelled: &mut P,
    ) -> Option<Result<StackPattern<T>, StackUnificationError>>
    where
        P: FnMut() -> bool,
        C: FnMut(&T, &mut P) -> Option<T>,
    {
        let mut fixed = clone_cells_with_poll(&pattern.fixed, clone_cell, cancelled)?;
        let mut tail = pattern.tail;
        let mut visited = HashSet::default();
        while let Some(variable) = tail {
            if cancelled() {
                return None;
            }
            let Some(binding) = self.binding(variable) else {
                break;
            };
            if !visited.insert(variable) {
                return Some(Err(StackUnificationError::RecursiveVariableBinding(
                    variable,
                )));
            }
            fixed.extend(clone_cells_with_poll(
                &binding.fixed,
                clone_cell,
                cancelled,
            )?);
            tail = binding.tail;
        }
        Some(Ok(StackPattern::new(fixed, tail)))
    }
}

fn clone_cells_with_poll<T, P, C>(
    values: &[T],
    clone_cell: &mut C,
    cancelled: &mut P,
) -> Option<Vec<T>>
where
    P: FnMut() -> bool,
    C: FnMut(&T, &mut P) -> Option<T>,
{
    let mut cloned = Vec::new();
    for value in values {
        cloned.push(clone_cell(value, cancelled)?);
    }
    Some(cloned)
}

fn clone_scope_stack_with_poll<P>(
    pattern: &ScopeStackPattern,
    cancelled: &mut P,
) -> Option<ScopeStackPattern>
where
    P: FnMut() -> bool,
{
    let mut clone_node = |node: &BindingNodeId, cancelled: &mut P| (!cancelled()).then_some(*node);
    let fixed = clone_cells_with_poll(&pattern.fixed, &mut clone_node, cancelled)?;
    if cancelled() {
        return None;
    }
    Some(StackPattern::new(fixed, pattern.tail))
}

fn alpha_rename_scope_stack_with_poll<P>(
    pattern: &ScopeStackPattern,
    renaming: AlphaRenamingId,
    cancelled: &mut P,
) -> Option<ScopeStackPattern>
where
    P: FnMut() -> bool,
{
    let mut cloned = clone_scope_stack_with_poll(pattern, cancelled)?;
    cloned.tail = cloned.tail.map(|variable| variable.alpha_renamed(renaming));
    Some(cloned)
}

fn clone_scoped_symbol_with_poll<P>(
    symbol: &PartialScopedSymbol,
    cancelled: &mut P,
) -> Option<PartialScopedSymbol>
where
    P: FnMut() -> bool,
{
    if cancelled() {
        return None;
    }
    Some(PartialScopedSymbol {
        symbol: symbol.symbol,
        scopes: match &symbol.scopes {
            Some(scopes) => Some(clone_scope_stack_with_poll(scopes, cancelled)?),
            None => None,
        },
    })
}

fn clone_symbol_stack_with_poll<P>(
    pattern: &SymbolStackPattern,
    cancelled: &mut P,
) -> Option<SymbolStackPattern>
where
    P: FnMut() -> bool,
{
    let mut clone_symbol = |symbol: &PartialScopedSymbol, cancelled: &mut P| {
        clone_scoped_symbol_with_poll(symbol, cancelled)
    };
    let fixed = clone_cells_with_poll(&pattern.fixed, &mut clone_symbol, cancelled)?;
    if cancelled() {
        return None;
    }
    Some(StackPattern::new(fixed, pattern.tail))
}

fn alpha_rename_scoped_symbol_with_poll<P>(
    symbol: &PartialScopedSymbol,
    renaming: AlphaRenamingId,
    cancelled: &mut P,
) -> Option<PartialScopedSymbol>
where
    P: FnMut() -> bool,
{
    if cancelled() {
        return None;
    }
    Some(PartialScopedSymbol {
        symbol: symbol.symbol,
        scopes: match &symbol.scopes {
            Some(scopes) => Some(alpha_rename_scope_stack_with_poll(
                scopes, renaming, cancelled,
            )?),
            None => None,
        },
    })
}

fn alpha_rename_symbol_stack_with_poll<P>(
    pattern: &SymbolStackPattern,
    renaming: AlphaRenamingId,
    cancelled: &mut P,
) -> Option<SymbolStackPattern>
where
    P: FnMut() -> bool,
{
    let mut clone_symbol = |symbol: &PartialScopedSymbol, cancelled: &mut P| {
        alpha_rename_scoped_symbol_with_poll(symbol, renaming, cancelled)
    };
    let fixed = clone_cells_with_poll(&pattern.fixed, &mut clone_symbol, cancelled)?;
    if cancelled() {
        return None;
    }
    Some(StackPattern::new(
        fixed,
        pattern
            .tail
            .map(|variable| variable.alpha_renamed(renaming)),
    ))
}

fn apply_symbol_stack_with_poll<P>(
    symbols: &StackSubstitution<PartialScopedSymbol>,
    scopes: &StackSubstitution<BindingNodeId>,
    pattern: &SymbolStackPattern,
    cancelled: &mut P,
) -> Option<Result<SymbolStackPattern, StackUnificationError>>
where
    P: FnMut() -> bool,
{
    let mut clone_symbol = |symbol: &PartialScopedSymbol, cancelled: &mut P| {
        clone_scoped_symbol_with_poll(symbol, cancelled)
    };
    let outer = match symbols.apply_with_poll(pattern, &mut clone_symbol, cancelled)? {
        Ok(outer) => outer,
        Err(error) => return Some(Err(error)),
    };
    let mut fixed = Vec::with_capacity(outer.fixed.len());
    for symbol in outer.fixed.iter() {
        if cancelled() {
            return None;
        }
        let substituted_scopes = match &symbol.scopes {
            Some(pattern) => {
                let mut clone_node =
                    |node: &BindingNodeId, cancelled: &mut P| (!cancelled()).then_some(*node);
                match scopes.apply_with_poll(pattern, &mut clone_node, cancelled)? {
                    Ok(scopes) => Some(scopes),
                    Err(error) => return Some(Err(error)),
                }
            }
            None => None,
        };
        fixed.push(PartialScopedSymbol {
            symbol: symbol.symbol,
            scopes: substituted_scopes,
        });
    }
    Some(Ok(StackPattern::new(fixed, outer.tail)))
}

fn unify_symbol_stacks_with_poll<P>(
    symbols: &mut StackSubstitution<PartialScopedSymbol>,
    scopes: &mut StackSubstitution<BindingNodeId>,
    left: &SymbolStackPattern,
    right: &SymbolStackPattern,
    cancelled: &mut P,
) -> Option<Result<(), StackUnificationError>>
where
    P: FnMut() -> bool,
{
    let left = match apply_symbol_stack_with_poll(symbols, scopes, left, cancelled)? {
        Ok(left) => left,
        Err(error) => return Some(Err(error)),
    };
    let right = match apply_symbol_stack_with_poll(symbols, scopes, right, cancelled)? {
        Ok(right) => right,
        Err(error) => return Some(Err(error)),
    };
    let shared = left.fixed.len().min(right.fixed.len());
    for index in 0..shared {
        if cancelled() {
            return None;
        }
        let left_symbol = &left.fixed[index];
        let right_symbol = &right.fixed[index];
        if left_symbol.symbol != right_symbol.symbol {
            return Some(Err(StackUnificationError::FixedCellMismatch { index }));
        }
        match (&left_symbol.scopes, &right_symbol.scopes) {
            (None, None) => {}
            (Some(left_scopes), Some(right_scopes)) => {
                let mut clone_node =
                    |node: &BindingNodeId, cancelled: &mut P| (!cancelled()).then_some(*node);
                match scopes.unify_patterns_with_poll(
                    left_scopes,
                    right_scopes,
                    &mut clone_node,
                    cancelled,
                )? {
                    Ok(()) => {}
                    Err(_) => {
                        return Some(Err(StackUnificationError::FixedCellMismatch { index }));
                    }
                }
            }
            (None, Some(_)) | (Some(_), None) => {
                return Some(Err(StackUnificationError::FixedCellMismatch { index }));
            }
        }
    }

    let left_remainder = &left.fixed[shared..];
    let right_remainder = &right.fixed[shared..];
    debug_assert!(left_remainder.is_empty() || right_remainder.is_empty());
    match (left_remainder.is_empty(), right_remainder.is_empty()) {
        (true, true) => match (left.tail, right.tail) {
            (None, None) => {}
            (Some(variable), None) | (None, Some(variable)) => {
                if let Err(error) = symbols.bind(variable, StackPattern::closed(Vec::new())) {
                    return Some(Err(error));
                }
            }
            (Some(left_variable), Some(right_variable)) if left_variable != right_variable => {
                if let Err(error) = symbols.bind(
                    left_variable,
                    StackPattern::open(Vec::new(), right_variable),
                ) {
                    return Some(Err(error));
                }
            }
            (Some(_), Some(_)) => {}
        },
        (true, false) => {
            let Some(variable) = left.tail else {
                return Some(Err(StackUnificationError::ClosedStackLengthMismatch));
            };
            let mut clone_symbol = |symbol: &PartialScopedSymbol, cancelled: &mut P| {
                clone_scoped_symbol_with_poll(symbol, cancelled)
            };
            let fixed = clone_cells_with_poll(right_remainder, &mut clone_symbol, cancelled)?;
            if let Err(error) = symbols.bind(variable, StackPattern::new(fixed, right.tail)) {
                return Some(Err(error));
            }
        }
        (false, true) => {
            let Some(variable) = right.tail else {
                return Some(Err(StackUnificationError::ClosedStackLengthMismatch));
            };
            let mut clone_symbol = |symbol: &PartialScopedSymbol, cancelled: &mut P| {
                clone_scoped_symbol_with_poll(symbol, cancelled)
            };
            let fixed = clone_cells_with_poll(left_remainder, &mut clone_symbol, cancelled)?;
            if let Err(error) = symbols.bind(variable, StackPattern::new(fixed, left.tail)) {
                return Some(Err(error));
            }
        }
        (false, false) => unreachable!("one fixed prefix must end first"),
    }
    Some(Ok(()))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointSignature {
    node: BindingNodeId,
    symbols: SymbolStackPattern,
    scopes: ScopeStackPattern,
}

impl EndpointSignature {
    pub fn new(
        node: BindingNodeId,
        symbols: StackPattern<SemanticId>,
        scopes: ScopeStackPattern,
    ) -> Self {
        Self::new_scoped(
            node,
            StackPattern::new(
                symbols
                    .fixed
                    .iter()
                    .copied()
                    .map(PartialScopedSymbol::unscoped)
                    .collect::<Vec<_>>(),
                symbols.tail,
            ),
            scopes,
        )
    }

    pub fn new_scoped(
        node: BindingNodeId,
        symbols: SymbolStackPattern,
        scopes: ScopeStackPattern,
    ) -> Self {
        Self {
            node,
            symbols,
            scopes,
        }
    }

    pub const fn node(&self) -> BindingNodeId {
        self.node
    }

    pub fn symbols(&self) -> &SymbolStackPattern {
        &self.symbols
    }

    pub fn scopes(&self) -> &ScopeStackPattern {
        &self.scopes
    }

    pub(crate) fn clone_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        if cancelled() {
            return None;
        }
        Some(Self::new_scoped(
            self.node,
            clone_symbol_stack_with_poll(&self.symbols, cancelled)?,
            clone_scope_stack_with_poll(&self.scopes, cancelled)?,
        ))
    }

    pub(crate) fn equals_with_poll<P>(&self, other: &Self, cancelled: &mut P) -> Option<bool>
    where
        P: FnMut() -> bool,
    {
        if self.node != other.node
            || self.symbols.tail != other.symbols.tail
            || self.symbols.fixed.len() != other.symbols.fixed.len()
            || self.scopes.tail != other.scopes.tail
            || self.scopes.fixed.len() != other.scopes.fixed.len()
        {
            return Some(false);
        }
        for (left, right) in self.symbols.fixed.iter().zip(other.symbols.fixed.iter()) {
            if cancelled() {
                return None;
            }
            if left.symbol != right.symbol {
                return Some(false);
            }
            match (left.scopes.as_ref(), right.scopes.as_ref()) {
                (None, None) => {}
                (Some(left), Some(right)) => {
                    if !scope_patterns_equal_with_poll(left, right, cancelled)? {
                        return Some(false);
                    }
                }
                (None, Some(_)) | (Some(_), None) => return Some(false),
            }
        }
        scope_patterns_equal_with_poll(&self.scopes, &other.scopes, cancelled)
    }

    fn alpha_renamed_with_poll<P>(
        &self,
        renaming: AlphaRenamingId,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        if cancelled() {
            return None;
        }
        Some(Self::new_scoped(
            self.node,
            alpha_rename_symbol_stack_with_poll(&self.symbols, renaming, cancelled)?,
            alpha_rename_scope_stack_with_poll(&self.scopes, renaming, cancelled)?,
        ))
    }

    fn substituted_with_poll<P>(
        &self,
        symbols: &StackSubstitution<PartialScopedSymbol>,
        scopes: &StackSubstitution<BindingNodeId>,
        cancelled: &mut P,
    ) -> Option<Result<Self, StackUnificationError>>
    where
        P: FnMut() -> bool,
    {
        if cancelled() {
            return None;
        }
        let symbols = match apply_symbol_stack_with_poll(symbols, scopes, &self.symbols, cancelled)?
        {
            Ok(symbols) => symbols,
            Err(error) => return Some(Err(error)),
        };
        let mut clone_node =
            |node: &BindingNodeId, cancelled: &mut P| (!cancelled()).then_some(*node);
        let scopes = match scopes.apply_with_poll(&self.scopes, &mut clone_node, cancelled)? {
            Ok(scopes) => scopes,
            Err(error) => return Some(Err(error)),
        };
        Some(Ok(Self::new_scoped(self.node, symbols, scopes)))
    }
}

fn scope_patterns_equal_with_poll<P>(
    left: &ScopeStackPattern,
    right: &ScopeStackPattern,
    cancelled: &mut P,
) -> Option<bool>
where
    P: FnMut() -> bool,
{
    if left.tail != right.tail || left.fixed.len() != right.fixed.len() {
        return Some(false);
    }
    for (left, right) in left.fixed.iter().zip(right.fixed.iter()) {
        if cancelled() {
            return None;
        }
        if left != right {
            return Some(false);
        }
    }
    Some(true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrecedenceStep {
    pub tier: PrecedenceTier,
    pub ordinal: u32,
    pub semantic: SemanticId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WitnessStep {
    Node(BindingNodeId),
    Candidate {
        semantic: SemanticId,
        outcome: CandidateOutcome,
    },
    Boundary {
        semantic: SemanticId,
        status: BoundaryStatus,
    },
}

impl WitnessStep {
    pub const fn kind(self) -> ResolutionWitnessKind {
        match self {
            Self::Node(_) => ResolutionWitnessKind::Node,
            Self::Candidate { .. } => ResolutionWitnessKind::Candidate,
            Self::Boundary { .. } => ResolutionWitnessKind::Boundary,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionIncompleteReason {
    Cancelled,
    CyclicExpansion(PartialPathId),
    /// Candidate precedence traces induce a cycle instead of a strict order.
    /// The engine preserves every candidate rather than manufacturing an
    /// empty answer, but cannot call that conservative ambiguity exact.
    InconsistentPrecedence(SemanticId),
    OpenBoundary {
        semantic: SemanticId,
        status: BoundaryStatus,
    },
    UnsupportedSemantic(SemanticId),
}

impl ResolutionIncompleteReason {
    pub const fn kind(self) -> ResolutionCompletionReasonKind {
        match self {
            Self::Cancelled => {
                panic!("operation-local cancellation has no persisted completion-reason kind")
            }
            Self::CyclicExpansion(_) => ResolutionCompletionReasonKind::CyclicExpansion,
            Self::InconsistentPrecedence(_) => {
                ResolutionCompletionReasonKind::InconsistentPrecedence
            }
            Self::OpenBoundary { .. } => ResolutionCompletionReasonKind::OpenBoundary,
            Self::UnsupportedSemantic(_) => ResolutionCompletionReasonKind::UnsupportedSemantic,
        }
    }
}

pub type CompletionReason = ResolutionIncompleteReason;

#[derive(Debug, Clone)]
pub enum ResolutionCompletion {
    Complete,
    Incomplete(CompletionReasons),
}

impl ResolutionCompletion {
    pub const fn kind(&self) -> ResolutionCompletionKind {
        match self {
            Self::Complete => ResolutionCompletionKind::Complete,
            Self::Incomplete(_) => ResolutionCompletionKind::Incomplete,
        }
    }

    pub fn incomplete(reasons: impl IntoIterator<Item = ResolutionIncompleteReason>) -> Self {
        let mut reasons = reasons.into_iter().collect::<Vec<_>>();
        reasons.sort_unstable();
        reasons.dedup();
        assert!(
            !reasons.is_empty(),
            "incomplete resolution requires a reason"
        );
        Self::Incomplete(CompletionReasons::canonical(reasons))
    }

    pub fn combine(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Complete, Self::Complete) => Self::Complete,
            (Self::Incomplete(reasons), Self::Complete)
            | (Self::Complete, Self::Incomplete(reasons)) => Self::Incomplete(reasons.clone()),
            (Self::Incomplete(left), Self::Incomplete(right)) => {
                Self::Incomplete(left.union(right))
            }
        }
    }

    pub(crate) fn contains_reason(&self, reason: ResolutionIncompleteReason) -> bool {
        matches!(self, Self::Incomplete(reasons) if reasons.contains(&reason))
    }
}

impl PartialEq for ResolutionCompletion {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Complete, Self::Complete) => true,
            (Self::Incomplete(left), Self::Incomplete(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for ResolutionCompletion {}

impl PartialOrd for ResolutionCompletion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ResolutionCompletion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::Complete, Self::Complete) => std::cmp::Ordering::Equal,
            (Self::Complete, Self::Incomplete(_)) => std::cmp::Ordering::Less,
            (Self::Incomplete(_), Self::Complete) => std::cmp::Ordering::Greater,
            (Self::Incomplete(left), Self::Incomplete(right)) => left.cmp(right),
        }
    }
}

impl std::hash::Hash for ResolutionCompletion {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::Complete => 0_u8.hash(state),
            Self::Incomplete(reasons) => {
                1_u8.hash(state);
                reasons.hash(state);
            }
        }
    }
}

/// A language-neutral type identity plus its pointer/reference indirection.
///
/// Indirection is explicit rather than folded into `identity`: Go method-set
/// and addressability rules need to distinguish `T`, `*T`, and `**T`, while
/// Java and other reference-only languages can use zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolutionTypeRef {
    identity: SemanticId,
    indirection: u32,
}

impl ResolutionTypeRef {
    pub const fn new(identity: SemanticId, indirection: u32) -> Self {
        Self {
            identity,
            indirection,
        }
    }

    pub const fn identity(self) -> SemanticId {
        self.identity
    }

    pub const fn indirection(self) -> u32 {
        self.indirection
    }
}

/// One value alternative at the binding/type-flow frontier.
///
/// Type objects participate in static-member and constructor lookup. Runtime
/// values participate in instance-member lookup and retain addressability for
/// languages whose method sets or implicit addressing depend on it. Keeping
/// these categories separate prevents a declaration identity from silently
/// changing meaning while it flows between slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionSlotValue {
    TypeObject(ResolutionTypeRef),
    Runtime {
        ty: ResolutionTypeRef,
        addressable: bool,
    },
}

impl ResolutionSlotValue {
    pub const fn type_object(ty: ResolutionTypeRef) -> Self {
        Self::TypeObject(ty)
    }

    pub const fn runtime(ty: ResolutionTypeRef, addressable: bool) -> Self {
        Self::Runtime { ty, addressable }
    }

    pub const fn ty(self) -> ResolutionTypeRef {
        match self {
            Self::TypeObject(ty) | Self::Runtime { ty, .. } => ty,
        }
    }

    pub const fn addressable(self) -> Option<bool> {
        match self {
            Self::TypeObject(_) => None,
            Self::Runtime { addressable, .. } => Some(addressable),
        }
    }
}

/// Explicit category transform applied while a value crosses a typed slot.
///
/// Category changes are facts, not engine guesses derived from a transfer's
/// prose role. For example, declared type syntax yields a type object, while
/// the declaration's value slot holds runtime values of that type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypeTransferValueTransform {
    Preserve,
    ToRuntime { addressable: bool },
    ToNoValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TypeTransferApplication {
    Value(ResolutionSlotValue),
    NoValue,
    IndirectionOutOfRange,
}

/// One immutable file-local rule that copies values between typed slots.
///
/// A rule deliberately stores no output values. Its output is a pure function
/// of the values supplied by the operation: category/addressability changes
/// are explicit in `value_transform`, while pointer/reference indirection is
/// adjusted with checked arithmetic. `semantic` is both the stable identity of
/// the rule and the evidence attached to an unrepresentable adjustment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeTransferRule {
    semantic: SemanticId,
    target_slot: SemanticId,
    indirection_delta: i64,
    value_transform: TypeTransferValueTransform,
    completion: ResolutionCompletion,
}

impl TypeTransferRule {
    pub const MIN_INDIRECTION_DELTA: i64 = -(u32::MAX as i64);
    pub const MAX_INDIRECTION_DELTA: i64 = u32::MAX as i64;

    pub fn new(
        semantic: SemanticId,
        target_slot: SemanticId,
        indirection_delta: i64,
        value_transform: TypeTransferValueTransform,
        completion: ResolutionCompletion,
    ) -> Self {
        assert!(
            (Self::MIN_INDIRECTION_DELTA..=Self::MAX_INDIRECTION_DELTA)
                .contains(&indirection_delta),
            "type-transfer indirection delta {indirection_delta} is outside the representable u32 range"
        );
        assert!(
            value_transform != TypeTransferValueTransform::ToNoValue || indirection_delta == 0,
            "a no-value transfer must not carry a meaningless indirection delta"
        );
        Self {
            semantic,
            target_slot,
            indirection_delta,
            value_transform,
            completion,
        }
    }

    pub const fn semantic(&self) -> SemanticId {
        self.semantic
    }

    pub const fn target_slot(&self) -> SemanticId {
        self.target_slot
    }

    pub const fn indirection_delta(&self) -> i64 {
        self.indirection_delta
    }

    pub const fn value_transform(&self) -> TypeTransferValueTransform {
        self.value_transform
    }

    pub fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }
    pub(super) fn apply(&self, value: ResolutionSlotValue) -> TypeTransferApplication {
        if self.value_transform == TypeTransferValueTransform::ToNoValue {
            return TypeTransferApplication::NoValue;
        }
        let ty = value.ty();
        let Some(adjusted) = i64::from(ty.indirection()).checked_add(self.indirection_delta) else {
            return TypeTransferApplication::IndirectionOutOfRange;
        };
        let Ok(adjusted) = u32::try_from(adjusted) else {
            return TypeTransferApplication::IndirectionOutOfRange;
        };
        let adjusted = ResolutionTypeRef::new(ty.identity(), adjusted);
        TypeTransferApplication::Value(match self.value_transform {
            TypeTransferValueTransform::Preserve => match value {
                ResolutionSlotValue::TypeObject(_) => ResolutionSlotValue::type_object(adjusted),
                ResolutionSlotValue::Runtime { addressable, .. } => {
                    ResolutionSlotValue::runtime(adjusted, addressable)
                }
            },
            TypeTransferValueTransform::ToRuntime { addressable } => {
                ResolutionSlotValue::runtime(adjusted, addressable)
            }
            TypeTransferValueTransform::ToNoValue => {
                unreachable!("no-value transfers return before type adjustment")
            }
        })
    }
}

/// The value alternatives at one point where binding hands work to type flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedFrontierState {
    slot: SemanticId,
    possible_values: Box<[ResolutionSlotValue]>,
    completion: ResolutionCompletion,
}

impl TypedFrontierState {
    pub(super) fn into_parts(
        self,
    ) -> (SemanticId, Box<[ResolutionSlotValue]>, ResolutionCompletion) {
        (self.slot, self.possible_values, self.completion)
    }

    pub(super) fn with_completion(mut self, completion: ResolutionCompletion) -> Self {
        self.completion = completion;
        self
    }

    pub fn new(
        slot: SemanticId,
        possible_values: impl Into<Box<[ResolutionSlotValue]>>,
        completion: ResolutionCompletion,
    ) -> Self {
        let mut possible_values = possible_values.into().into_vec();
        possible_values.sort_unstable();
        possible_values.dedup();
        Self {
            slot,
            possible_values: possible_values.into_boxed_slice(),
            completion,
        }
    }

    pub const fn slot(&self) -> SemanticId {
        self.slot
    }

    pub fn possible_values(&self) -> &[ResolutionSlotValue] {
        &self.possible_values
    }

    pub fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }

    /// Rebuild an already-canonical frontier without sorting its values again.
    pub(super) fn from_canonical_parts(
        slot: SemanticId,
        possible_values: Box<[ResolutionSlotValue]>,
        completion: ResolutionCompletion,
        mut cancelled: impl FnMut() -> bool,
    ) -> Option<Self> {
        for pair in possible_values.windows(2) {
            if cancelled() {
                return None;
            }
            assert!(
                pair[0] < pair[1],
                "canonical frontier values must be strictly sorted and deduplicated"
            );
        }
        Some(Self {
            slot,
            possible_values,
            completion,
        })
    }
}

/// Stable evidence for one selected or rejected semantic candidate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolutionWitness {
    reference: SemanticId,
    target: SemanticId,
    steps: Box<[WitnessStep]>,
    completion: ResolutionCompletion,
}

impl ResolutionWitness {
    pub(super) fn into_parts(
        self,
    ) -> (
        SemanticId,
        SemanticId,
        Box<[WitnessStep]>,
        ResolutionCompletion,
    ) {
        (self.reference, self.target, self.steps, self.completion)
    }

    pub fn new(
        reference: SemanticId,
        target: SemanticId,
        steps: impl Into<Box<[WitnessStep]>>,
        completion: ResolutionCompletion,
    ) -> Self {
        Self {
            reference,
            target,
            steps: steps.into(),
            completion,
        }
    }

    pub const fn reference(&self) -> SemanticId {
        self.reference
    }

    pub const fn target(&self) -> SemanticId {
        self.target
    }

    pub fn steps(&self) -> &[WitnessStep] {
        &self.steps
    }

    pub fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }
}

/// One point-resolution result. Ambiguity is a complete multi-target answer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolutionAnswer {
    targets: Box<[SemanticId]>,
    witnesses: Box<[ResolutionWitness]>,
    completion: ResolutionCompletion,
}

impl ResolutionAnswer {
    pub fn new(
        targets: impl Into<Box<[SemanticId]>>,
        witnesses: impl Into<Box<[ResolutionWitness]>>,
        completion: ResolutionCompletion,
    ) -> Self {
        Self {
            targets: targets.into(),
            witnesses: witnesses.into(),
            completion,
        }
    }

    pub fn targets(&self) -> &[SemanticId] {
        &self.targets
    }

    pub fn witnesses(&self) -> &[ResolutionWitness] {
        &self.witnesses
    }

    pub fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        Box<[SemanticId]>,
        Box<[ResolutionWitness]>,
        ResolutionCompletion,
    ) {
        (self.targets, self.witnesses, self.completion)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PartialPath {
    start: EndpointSignature,
    end: EndpointSignature,
    precedence: Box<[PrecedenceStep]>,
    witness: Box<[WitnessStep]>,
    completion: ResolutionCompletion,
}

/// Exact, hashable alpha-normal form of a path's endpoint stack behavior.
/// Variable ordinals preserve aliasing across both endpoints. Symbol-tail and
/// scope-tail variables occupy separate namespaces because they are unified
/// by separate substitutions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct StackEffectAlphaKey {
    start: AlphaEndpointKey,
    end: AlphaEndpointKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AlphaEndpointKey {
    node: BindingNodeId,
    symbols: AlphaSymbolStackKey,
    scopes: AlphaStackKey<BindingNodeId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AlphaSymbolStackKey {
    fixed: Box<[AlphaScopedSymbolKey]>,
    tail: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AlphaScopedSymbolKey {
    symbol: SemanticId,
    scopes: Option<AlphaStackKey<BindingNodeId>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AlphaStackKey<T> {
    fixed: Box<[T]>,
    tail: Option<u32>,
}

impl StackEffectAlphaKey {
    pub(crate) fn clone_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        Some(Self {
            start: clone_alpha_endpoint_with_poll(&self.start, cancelled)?,
            end: clone_alpha_endpoint_with_poll(&self.end, cancelled)?,
        })
    }

    pub(crate) fn equals_with_poll<P>(&self, other: &Self, cancelled: &mut P) -> Option<bool>
    where
        P: FnMut() -> bool,
    {
        Some(
            alpha_endpoints_equal_with_poll(&self.start, &other.start, cancelled)?
                && alpha_endpoints_equal_with_poll(&self.end, &other.end, cancelled)?,
        )
    }

    pub(crate) fn canonical_digest_with_poll<P>(&self, cancelled: &mut P) -> Option<[u8; 32]>
    where
        P: FnMut() -> bool,
    {
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-stack-effect-alpha-key:v1");
        hash_alpha_endpoint_with_poll(&mut hasher, b"start", &self.start, cancelled)?;
        hash_alpha_endpoint_with_poll(&mut hasher, b"end", &self.end, cancelled)?;
        Some(hasher.finish())
    }
}

fn clone_alpha_endpoint_with_poll<P>(
    endpoint: &AlphaEndpointKey,
    cancelled: &mut P,
) -> Option<AlphaEndpointKey>
where
    P: FnMut() -> bool,
{
    let mut symbols = Vec::with_capacity(endpoint.symbols.fixed.len());
    for symbol in endpoint.symbols.fixed.iter() {
        if cancelled() {
            return None;
        }
        symbols.push(AlphaScopedSymbolKey {
            symbol: symbol.symbol,
            scopes: match symbol.scopes.as_ref() {
                Some(scopes) => Some(clone_alpha_scope_stack_with_poll(scopes, cancelled)?),
                None => None,
            },
        });
    }
    Some(AlphaEndpointKey {
        node: endpoint.node,
        symbols: AlphaSymbolStackKey {
            fixed: symbols.into_boxed_slice(),
            tail: endpoint.symbols.tail,
        },
        scopes: clone_alpha_scope_stack_with_poll(&endpoint.scopes, cancelled)?,
    })
}

fn clone_alpha_scope_stack_with_poll<P>(
    stack: &AlphaStackKey<BindingNodeId>,
    cancelled: &mut P,
) -> Option<AlphaStackKey<BindingNodeId>>
where
    P: FnMut() -> bool,
{
    Some(AlphaStackKey {
        fixed: clone_copy_slice_with_poll(&stack.fixed, cancelled)?.into_boxed_slice(),
        tail: stack.tail,
    })
}

fn alpha_endpoints_equal_with_poll<P>(
    left: &AlphaEndpointKey,
    right: &AlphaEndpointKey,
    cancelled: &mut P,
) -> Option<bool>
where
    P: FnMut() -> bool,
{
    if left.node != right.node
        || left.symbols.tail != right.symbols.tail
        || left.symbols.fixed.len() != right.symbols.fixed.len()
    {
        return Some(false);
    }
    for (left, right) in left.symbols.fixed.iter().zip(right.symbols.fixed.iter()) {
        if cancelled() {
            return None;
        }
        if left.symbol != right.symbol {
            return Some(false);
        }
        match (left.scopes.as_ref(), right.scopes.as_ref()) {
            (None, None) => {}
            (Some(left), Some(right)) => {
                if !alpha_scope_stacks_equal_with_poll(left, right, cancelled)? {
                    return Some(false);
                }
            }
            (None, Some(_)) | (Some(_), None) => return Some(false),
        }
    }
    alpha_scope_stacks_equal_with_poll(&left.scopes, &right.scopes, cancelled)
}

fn alpha_scope_stacks_equal_with_poll<P>(
    left: &AlphaStackKey<BindingNodeId>,
    right: &AlphaStackKey<BindingNodeId>,
    cancelled: &mut P,
) -> Option<bool>
where
    P: FnMut() -> bool,
{
    if left.tail != right.tail || left.fixed.len() != right.fixed.len() {
        return Some(false);
    }
    for (left, right) in left.fixed.iter().zip(right.fixed.iter()) {
        if cancelled() {
            return None;
        }
        if left != right {
            return Some(false);
        }
    }
    Some(true)
}

fn hash_alpha_endpoint_with_poll<P>(
    hasher: &mut CanonicalHasher,
    label: &[u8],
    endpoint: &AlphaEndpointKey,
    cancelled: &mut P,
) -> Option<()>
where
    P: FnMut() -> bool,
{
    hasher.value(label);
    hasher.value(&endpoint.node.as_bytes());
    hasher.value(&(endpoint.symbols.fixed.len() as u64).to_le_bytes());
    hash_optional_ordinal(hasher, endpoint.symbols.tail);
    for symbol in endpoint.symbols.fixed.iter() {
        if cancelled() {
            return None;
        }
        hasher.value(&symbol.symbol.as_bytes());
        match symbol.scopes.as_ref() {
            Some(scopes) => {
                hasher.value(b"scoped");
                hash_alpha_scope_stack_with_poll(hasher, scopes, cancelled)?;
            }
            None => hasher.value(b"unscoped"),
        }
    }
    hash_alpha_scope_stack_with_poll(hasher, &endpoint.scopes, cancelled)
}

fn hash_alpha_scope_stack_with_poll<P>(
    hasher: &mut CanonicalHasher,
    stack: &AlphaStackKey<BindingNodeId>,
    cancelled: &mut P,
) -> Option<()>
where
    P: FnMut() -> bool,
{
    hasher.value(&(stack.fixed.len() as u64).to_le_bytes());
    hash_optional_ordinal(hasher, stack.tail);
    for node in stack.fixed.iter() {
        if cancelled() {
            return None;
        }
        hasher.value(&node.as_bytes());
    }
    Some(())
}

fn hash_optional_ordinal(hasher: &mut CanonicalHasher, ordinal: Option<u32>) {
    match ordinal {
        Some(ordinal) => {
            hasher.value(b"some");
            hasher.value(&ordinal.to_le_bytes());
        }
        None => hasher.value(b"none"),
    }
}

#[derive(Default)]
struct AlphaNormalizer {
    symbol_variables: HashMap<StackVariableId, u32>,
    scope_variables: HashMap<StackVariableId, u32>,
}

impl AlphaNormalizer {
    fn symbol_variable(&mut self, variable: StackVariableId) -> u32 {
        let next = self.symbol_variables.len() as u32;
        *self.symbol_variables.entry(variable).or_insert(next)
    }

    fn scope_variable(&mut self, variable: StackVariableId) -> u32 {
        let next = self.scope_variables.len() as u32;
        *self.scope_variables.entry(variable).or_insert(next)
    }

    fn scope_stack_with_poll<P>(
        &mut self,
        pattern: &ScopeStackPattern,
        cancelled: &mut P,
    ) -> Option<AlphaStackKey<BindingNodeId>>
    where
        P: FnMut() -> bool,
    {
        Some(AlphaStackKey {
            fixed: clone_copy_slice_with_poll(&pattern.fixed, cancelled)?.into_boxed_slice(),
            tail: pattern.tail.map(|variable| self.scope_variable(variable)),
        })
    }

    fn symbol_stack_with_poll<P>(
        &mut self,
        pattern: &SymbolStackPattern,
        cancelled: &mut P,
    ) -> Option<AlphaSymbolStackKey>
    where
        P: FnMut() -> bool,
    {
        let mut fixed = Vec::with_capacity(pattern.fixed.len());
        for cell in pattern.fixed.iter() {
            if cancelled() {
                return None;
            }
            fixed.push(AlphaScopedSymbolKey {
                symbol: cell.symbol,
                scopes: match cell.scopes.as_ref() {
                    Some(scopes) => Some(self.scope_stack_with_poll(scopes, cancelled)?),
                    None => None,
                },
            });
        }
        Some(AlphaSymbolStackKey {
            fixed: fixed.into_boxed_slice(),
            tail: pattern.tail.map(|variable| self.symbol_variable(variable)),
        })
    }

    fn endpoint_with_poll<P>(
        &mut self,
        endpoint: &EndpointSignature,
        cancelled: &mut P,
    ) -> Option<AlphaEndpointKey>
    where
        P: FnMut() -> bool,
    {
        Some(AlphaEndpointKey {
            node: endpoint.node,
            symbols: self.symbol_stack_with_poll(&endpoint.symbols, cancelled)?,
            scopes: self.scope_stack_with_poll(&endpoint.scopes, cancelled)?,
        })
    }
}

fn clone_copy_slice_with_poll<T: Copy, P>(values: &[T], cancelled: &mut P) -> Option<Vec<T>>
where
    P: FnMut() -> bool,
{
    if cancelled() {
        return None;
    }
    let mut cloned = Vec::with_capacity(values.len());
    for &value in values {
        if cancelled() {
            return None;
        }
        cloned.push(value);
    }
    Some(cloned)
}

pub(crate) fn clone_completion_with_poll<P>(
    completion: &ResolutionCompletion,
    cancelled: &mut P,
) -> Option<ResolutionCompletion>
where
    P: FnMut() -> bool,
{
    match completion {
        ResolutionCompletion::Complete => Some(ResolutionCompletion::Complete),
        ResolutionCompletion::Incomplete(reasons) => Some(ResolutionCompletion::Incomplete(
            reasons.clone_with_poll(cancelled)?,
        )),
    }
}

pub(crate) fn combine_completion_with_poll<P>(
    left: &ResolutionCompletion,
    right: &ResolutionCompletion,
    cancelled: &mut P,
) -> Option<ResolutionCompletion>
where
    P: FnMut() -> bool,
{
    match (left, right) {
        (ResolutionCompletion::Complete, ResolutionCompletion::Complete) => {
            Some(ResolutionCompletion::Complete)
        }
        (ResolutionCompletion::Incomplete(_), ResolutionCompletion::Complete) => {
            clone_completion_with_poll(left, cancelled)
        }
        (ResolutionCompletion::Complete, ResolutionCompletion::Incomplete(_)) => {
            clone_completion_with_poll(right, cancelled)
        }
        (ResolutionCompletion::Incomplete(left), ResolutionCompletion::Incomplete(right)) => Some(
            ResolutionCompletion::Incomplete(left.union_with_poll(right, cancelled)?),
        ),
    }
}

fn assert_semantic_completion_with_poll<P>(
    completion: &ResolutionCompletion,
    cancelled: &mut P,
) -> Option<()>
where
    P: FnMut() -> bool,
{
    if let ResolutionCompletion::Incomplete(reasons) = completion {
        for &reason in reasons.iter() {
            if cancelled() {
                return None;
            }
            assert_ne!(
                reason,
                ResolutionIncompleteReason::Cancelled,
                "partial-path completion cannot contain operation-local cancellation"
            );
        }
    }
    Some(())
}

impl PartialPath {
    pub fn new(
        start: EndpointSignature,
        end: EndpointSignature,
        precedence: impl Into<Box<[PrecedenceStep]>>,
        witness: impl Into<Box<[WitnessStep]>>,
        completion: ResolutionCompletion,
    ) -> Self {
        let Some(path) = Self::new_with_poll(
            start,
            end,
            precedence.into(),
            witness.into(),
            completion,
            &mut never_cancelled,
        ) else {
            unreachable!("the never-cancelled partial-path poll returned cancellation")
        };
        path
    }

    pub(crate) fn new_with_poll<P>(
        start: EndpointSignature,
        end: EndpointSignature,
        precedence: Box<[PrecedenceStep]>,
        witness: Box<[WitnessStep]>,
        completion: ResolutionCompletion,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        if cancelled() {
            return None;
        }
        assert_semantic_completion_with_poll(&completion, cancelled)?;
        if cancelled() {
            return None;
        }
        Some(Self {
            start,
            end,
            precedence,
            witness,
            completion,
        })
    }

    pub fn start(&self) -> &EndpointSignature {
        &self.start
    }

    pub fn end(&self) -> &EndpointSignature {
        &self.end
    }

    pub fn precedence(&self) -> &[PrecedenceStep] {
        &self.precedence
    }

    pub fn witness(&self) -> &[WitnessStep] {
        &self.witness
    }

    pub fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }

    pub(crate) fn with_additional_completion(mut self, completion: &ResolutionCompletion) -> Self {
        assert!(
            !completion.contains_reason(ResolutionIncompleteReason::Cancelled),
            "partial-path completion cannot contain operation-local cancellation"
        );
        self.completion = self.completion.combine(completion);
        self
    }

    pub(crate) fn with_additional_completion_with_poll<P>(
        mut self,
        completion: &ResolutionCompletion,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        assert_semantic_completion_with_poll(completion, cancelled)?;
        self.completion = combine_completion_with_poll(&self.completion, completion, cancelled)?;
        Some(self)
    }

    pub(crate) fn with_seed_completion_with_poll<P>(
        mut self,
        seed_completion: &ResolutionCompletion,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        let completion =
            combine_completion_with_poll(seed_completion, &self.completion, cancelled)?;
        assert_semantic_completion_with_poll(&completion, cancelled)?;
        self.completion = completion;
        Some(self)
    }

    pub(crate) fn equals_with_poll<P>(&self, other: &Self, cancelled: &mut P) -> Option<bool>
    where
        P: FnMut() -> bool,
    {
        if !self.start.equals_with_poll(&other.start, cancelled)?
            || !self.end.equals_with_poll(&other.end, cancelled)?
            || self.precedence.len() != other.precedence.len()
            || self.witness.len() != other.witness.len()
        {
            return Some(false);
        }
        for (left, right) in self.precedence.iter().zip(other.precedence.iter()) {
            if cancelled() {
                return None;
            }
            if left != right {
                return Some(false);
            }
        }
        for (left, right) in self.witness.iter().zip(other.witness.iter()) {
            if cancelled() {
                return None;
            }
            if left != right {
                return Some(false);
            }
        }
        completion_values_equal_with_poll(&self.completion, &other.completion, cancelled)
    }

    pub(crate) fn stack_effect_alpha_key_with_poll<P>(
        &self,
        cancelled: &mut P,
    ) -> Option<StackEffectAlphaKey>
    where
        P: FnMut() -> bool,
    {
        let mut normalizer = AlphaNormalizer::default();
        Some(StackEffectAlphaKey {
            start: normalizer.endpoint_with_poll(&self.start, cancelled)?,
            end: normalizer.endpoint_with_poll(&self.end, cancelled)?,
        })
    }

    /// Collapse repeated semantic evidence to the same finite representative
    /// used by cycle saturation. This makes the retained replay witness
    /// independent of which equivalent route reaches the quotient first.
    pub(crate) fn canonicalized_observations(self) -> Self {
        let Some(path) = self.canonicalized_observations_with_poll(&mut never_cancelled) else {
            unreachable!("the never-cancelled observation poll returned cancellation")
        };
        path
    }

    pub(crate) fn canonicalized_observations_with_poll<P>(
        mut self,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        self.precedence = first_occurrences_with_poll(&self.precedence, cancelled)?;
        self.witness = first_occurrences_with_poll(&self.witness, cancelled)?;
        Some(self)
    }

    pub(crate) fn clone_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        Some(Self {
            start: self.start.clone_with_poll(cancelled)?,
            end: self.end.clone_with_poll(cancelled)?,
            precedence: clone_copy_slice_with_poll(&self.precedence, cancelled)?.into_boxed_slice(),
            witness: clone_copy_slice_with_poll(&self.witness, cancelled)?.into_boxed_slice(),
            completion: clone_completion_with_poll(&self.completion, cancelled)?,
        })
    }

    pub(super) fn alpha_renamed_with_poll<P>(
        &self,
        renaming: AlphaRenamingId,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        Some(Self {
            start: self.start.alpha_renamed_with_poll(renaming, cancelled)?,
            end: self.end.alpha_renamed_with_poll(renaming, cancelled)?,
            precedence: clone_copy_slice_with_poll(&self.precedence, cancelled)?.into_boxed_slice(),
            witness: clone_copy_slice_with_poll(&self.witness, cancelled)?.into_boxed_slice(),
            completion: clone_completion_with_poll(&self.completion, cancelled)?,
        })
    }

    pub fn concatenate(
        &self,
        next: &Self,
        next_renaming: AlphaRenamingId,
    ) -> Result<Self, PathCompositionError> {
        let Some(result) = self.concatenate_with_poll(next, next_renaming, &mut never_cancelled)
        else {
            unreachable!("the never-cancelled composition poll returned cancellation")
        };
        result
    }

    pub(crate) fn concatenate_with_poll<P>(
        &self,
        next: &Self,
        next_renaming: AlphaRenamingId,
        cancelled: &mut P,
    ) -> Option<Result<Self, PathCompositionError>>
    where
        P: FnMut() -> bool,
    {
        if cancelled() {
            return None;
        }
        let next = next.alpha_renamed_with_poll(next_renaming, cancelled)?;
        let (symbols, scopes) =
            match unify_middle_endpoints_with_poll(&self.end, &next.start, cancelled)? {
                Ok(substitutions) => substitutions,
                Err(error) => return Some(Err(error)),
            };

        let start = match self
            .start
            .substituted_with_poll(&symbols, &scopes, cancelled)?
        {
            Ok(start) => start,
            Err(error) => return Some(Err(PathCompositionError::Substitution(error))),
        };
        let end = match next
            .end
            .substituted_with_poll(&symbols, &scopes, cancelled)?
        {
            Ok(end) => end,
            Err(error) => return Some(Err(PathCompositionError::Substitution(error))),
        };

        let mut precedence = Vec::with_capacity(self.precedence.len() + next.precedence.len());
        precedence.extend(clone_copy_slice_with_poll(&self.precedence, cancelled)?);
        precedence.extend(clone_copy_slice_with_poll(&next.precedence, cancelled)?);
        let mut witness = Vec::with_capacity(self.witness.len() + next.witness.len());
        witness.extend(clone_copy_slice_with_poll(&self.witness, cancelled)?);
        witness.extend(clone_copy_slice_with_poll(&next.witness, cancelled)?);
        let completion =
            combine_completion_with_poll(&self.completion, &next.completion, cancelled)?;

        Some(Ok(Self {
            start,
            end,
            precedence: precedence.into_boxed_slice(),
            witness: witness.into_boxed_slice(),
            completion,
        }))
    }
}

type MiddleEndpointUnification = Result<
    (
        StackSubstitution<PartialScopedSymbol>,
        StackSubstitution<BindingNodeId>,
    ),
    PathCompositionError,
>;

fn unify_middle_endpoints_with_poll<P>(
    left: &EndpointSignature,
    right: &EndpointSignature,
    cancelled: &mut P,
) -> Option<MiddleEndpointUnification>
where
    P: FnMut() -> bool,
{
    if left.node != right.node {
        return Some(Err(PathCompositionError::EndpointMismatch {
            left: left.node,
            right: right.node,
        }));
    }
    let mut symbols = StackSubstitution::default();
    let mut scopes = StackSubstitution::default();
    match unify_symbol_stacks_with_poll(
        &mut symbols,
        &mut scopes,
        &left.symbols,
        &right.symbols,
        cancelled,
    )? {
        Ok(()) => {}
        Err(error) => return Some(Err(PathCompositionError::SymbolStack(error))),
    }
    let mut clone_node = |node: &BindingNodeId, cancelled: &mut P| (!cancelled()).then_some(*node);
    match scopes.unify_patterns_with_poll(
        &left.scopes,
        &right.scopes,
        &mut clone_node,
        cancelled,
    )? {
        Ok(()) => Some(Ok((symbols, scopes))),
        Err(error) => Some(Err(PathCompositionError::ScopeStack(error))),
    }
}

pub(crate) fn completion_values_equal_with_poll<P>(
    left: &ResolutionCompletion,
    right: &ResolutionCompletion,
    cancelled: &mut P,
) -> Option<bool>
where
    P: FnMut() -> bool,
{
    match (left, right) {
        (ResolutionCompletion::Complete, ResolutionCompletion::Complete) => Some(true),
        (ResolutionCompletion::Incomplete(left), ResolutionCompletion::Incomplete(right)) => {
            left.equals_with_poll(right, cancelled)
        }
        (ResolutionCompletion::Complete, ResolutionCompletion::Incomplete(_))
        | (ResolutionCompletion::Incomplete(_), ResolutionCompletion::Complete) => Some(false),
    }
}

fn first_occurrences_with_poll<T: Copy + Eq + std::hash::Hash, P>(
    values: &[T],
    cancelled: &mut P,
) -> Option<Box<[T]>>
where
    P: FnMut() -> bool,
{
    let mut seen = HashSet::default();
    let mut first = Vec::with_capacity(values.len());
    for &value in values {
        if cancelled() {
            return None;
        }
        if seen.insert(value) {
            first.push(value);
        }
    }
    Some(first.into_boxed_slice())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathCompositionError {
    EndpointMismatch {
        left: BindingNodeId,
        right: BindingNodeId,
    },
    SymbolStack(StackUnificationError),
    ScopeStack(StackUnificationError),
    Substitution(StackUnificationError),
}

impl fmt::Display for PathCompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndpointMismatch { left, right } => {
                write!(formatter, "path endpoints differ: {left} != {right}")
            }
            Self::SymbolStack(error) => write!(formatter, "symbol stack: {error}"),
            Self::ScopeStack(error) => write!(formatter, "scope stack: {error}"),
            Self::Substitution(error) => write!(formatter, "path substitution: {error}"),
        }
    }
}

impl std::error::Error for PathCompositionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn semantic(value: &str) -> SemanticId {
        SemanticId::hash_bytes(value)
    }

    fn variable(value: &str) -> StackVariableId {
        StackVariableId::hash_bytes(value)
    }

    fn node(value: &str) -> BindingNodeId {
        BindingNodeId::hash_bytes(value)
    }

    fn unify_patterns(
        left: &StackPattern<SemanticId>,
        right: &StackPattern<SemanticId>,
    ) -> Result<StackSubstitution<SemanticId>, StackUnificationError> {
        let mut substitution = StackSubstitution::default();
        let mut clone_cell = |cell: &SemanticId, _: &mut _| Some(*cell);
        substitution
            .unify_patterns_with_poll(left, right, &mut clone_cell, &mut || false)
            .expect("live test unification completes")?;
        Ok(substitution)
    }

    fn apply_substitution(
        substitution: &StackSubstitution<SemanticId>,
        pattern: &StackPattern<SemanticId>,
    ) -> Result<StackPattern<SemanticId>, StackUnificationError> {
        let mut clone_cell = |cell: &SemanticId, _: &mut _| Some(*cell);
        substitution
            .apply_with_poll(pattern, &mut clone_cell, &mut || false)
            .expect("live test substitution completes")
    }

    fn endpoint(
        node: BindingNodeId,
        symbols: Vec<SemanticId>,
        scopes: Vec<BindingNodeId>,
    ) -> EndpointSignature {
        EndpointSignature::new(
            node,
            StackPattern::closed(symbols),
            StackPattern::closed(scopes),
        )
    }

    #[test]
    fn fragment_local_keys_have_globally_distinct_mounted_identities() {
        let first = BindingFragmentId::hash_bytes("first-fragment");
        let second = BindingFragmentId::hash_bytes("second-fragment");

        assert_ne!(
            BindingNodeId::in_fragment(first, b"same-local-key"),
            BindingNodeId::in_fragment(second, b"same-local-key")
        );
        assert_ne!(
            PartialPathId::in_fragment(first, b"same-local-key"),
            PartialPathId::in_fragment(second, b"same-local-key")
        );
        assert_ne!(
            SemanticId::in_fragment(first, b"same-local-key"),
            SemanticId::in_fragment(second, b"same-local-key")
        );
        assert_ne!(
            StackVariableId::in_fragment(first, b"same-local-key"),
            StackVariableId::in_fragment(second, b"same-local-key")
        );
        assert_eq!(
            PartialPathId::in_fragment(first, b"same-local-key"),
            PartialPathId::in_fragment(first, b"same-local-key")
        );
    }

    #[test]
    #[should_panic(
        expected = "partial-path completion cannot contain operation-local cancellation"
    )]
    fn partial_paths_reject_operation_local_cancellation_evidence() {
        let endpoint = EndpointSignature::new(
            node("cancelled-path-endpoint"),
            StackPattern::closed(Vec::new()),
            StackPattern::closed(Vec::new()),
        );

        PartialPath::new(
            endpoint.clone(),
            endpoint,
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
        );
    }

    #[test]
    fn unification_binds_the_shorter_open_prefix() {
        let remainder = variable("remainder");
        let left = StackPattern::open(vec![semantic("a")], remainder);
        let right = StackPattern::closed(vec![semantic("a"), semantic("b")]);

        let substitution = unify_patterns(&left, &right).expect("patterns unify");

        assert_eq!(
            substitution.binding(remainder),
            Some(&StackPattern::closed(vec![semantic("b")]))
        );
        assert_eq!(apply_substitution(&substitution, &left).unwrap(), right);
    }

    #[test]
    fn unification_rejects_mismatched_and_recursive_patterns() {
        let remainder = variable("remainder");
        assert_eq!(
            unify_patterns(
                &StackPattern::closed(vec![semantic("a")]),
                &StackPattern::closed(vec![semantic("b")]),
            ),
            Err(StackUnificationError::FixedCellMismatch { index: 0 })
        );
        assert_eq!(
            unify_patterns(
                &StackPattern::open(Vec::<SemanticId>::new(), remainder),
                &StackPattern::open(vec![semantic("a")], remainder),
            ),
            Err(StackUnificationError::RecursiveVariableBinding(remainder))
        );
    }

    #[test]
    fn concatenation_unifies_middle_stacks_and_preserves_evidence() {
        let tail = variable("tail");
        let scope_tail = variable("scope-tail");
        let seam = node("seam");
        let left = PartialPath::new(
            EndpointSignature::new(
                node("left-start"),
                StackPattern::open(Vec::new(), tail),
                StackPattern::open(Vec::new(), scope_tail),
            ),
            EndpointSignature::new(
                seam,
                StackPattern::open(vec![semantic("name")], tail),
                StackPattern::open(vec![node("scope")], scope_tail),
            ),
            vec![PrecedenceStep {
                semantic: semantic("left"),
                tier: PrecedenceTier::LexicalBinding,
                ordinal: 0,
            }],
            vec![WitnessStep::Node(seam)],
            ResolutionCompletion::Complete,
        );
        let right = PartialPath::new(
            EndpointSignature::new(
                seam,
                StackPattern::closed(vec![semantic("name")]),
                StackPattern::closed(vec![node("scope")]),
            ),
            EndpointSignature::new(
                node("right-end"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            vec![PrecedenceStep {
                semantic: semantic("right"),
                tier: PrecedenceTier::OwnMember,
                ordinal: 0,
            }],
            vec![WitnessStep::Candidate {
                semantic: semantic("target"),
                outcome: CandidateOutcome::Selected,
            }],
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::OpenBoundary {
                semantic: semantic("dependency"),
                status: BoundaryStatus::ExternalDeclaredUnindexed,
            }]),
        );

        let joined = left
            .concatenate(&right, AlphaRenamingId::hash_bytes("right-use"))
            .expect("middle signatures compose");
        let mut polls = 0_usize;
        let polled = left
            .concatenate_with_poll(
                &right,
                AlphaRenamingId::hash_bytes("right-use"),
                &mut || {
                    polls += 1;
                    false
                },
            )
            .expect("an uncancelled composition is not cancelled")
            .expect("middle signatures compose through the polled seam");

        assert_eq!(polled, joined);
        assert!(polls > 0);
        assert_eq!(joined.start().symbols(), &StackPattern::closed(Vec::new()));
        assert_eq!(joined.start().scopes(), &StackPattern::closed(Vec::new()));
        assert_eq!(joined.end(), right.end());
        assert_eq!(joined.precedence().len(), 2);
        assert_eq!(joined.witness().len(), 2);
        assert!(matches!(
            joined.completion(),
            ResolutionCompletion::Incomplete(reasons) if reasons.len() == 1
        ));
    }

    #[test]
    fn polled_concatenation_preserves_public_noncanonical_completion_semantics() {
        let seam = node("noncanonical-completion-seam");
        let first = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            "noncanonical-completion-first",
        ));
        let second = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            "noncanonical-completion-second",
        ));
        let left_completion =
            ResolutionCompletion::Incomplete(CompletionReasons::from(vec![second, first, second]));
        let right_completion =
            ResolutionCompletion::Incomplete(CompletionReasons::from(vec![first, second, first]));
        let left = PartialPath::new(
            EndpointSignature::new(
                node("noncanonical-completion-start"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            EndpointSignature::new(
                seam,
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            Vec::new(),
            Vec::new(),
            left_completion.clone(),
        );
        let right = PartialPath::new(
            EndpointSignature::new(
                seam,
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            EndpointSignature::new(
                node("noncanonical-completion-end"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            Vec::new(),
            Vec::new(),
            right_completion.clone(),
        );
        let expected = left_completion.combine(&right_completion);

        let public = left
            .concatenate(
                &right,
                AlphaRenamingId::hash_bytes("noncanonical-completion-public"),
            )
            .expect("compatible paths concatenate");
        let polled = left
            .concatenate_with_poll(
                &right,
                AlphaRenamingId::hash_bytes("noncanonical-completion-public"),
                &mut || false,
            )
            .expect("uncancelled structural work completes")
            .expect("compatible paths concatenate");

        assert_eq!(public.completion(), &expected);
        assert_eq!(polled, public);
        assert_eq!(
            expected,
            ResolutionCompletion::Incomplete(CompletionReasons::from(vec![first, second]))
        );
    }

    #[test]
    fn concatenation_preserves_the_public_two_empty_incomplete_panic() {
        let seam = node("empty-incomplete-seam");
        let empty = ResolutionCompletion::Incomplete(CompletionReasons::from(Vec::new()));
        let left = PartialPath::new(
            endpoint(node("empty-incomplete-left"), Vec::new(), Vec::new()),
            endpoint(seam, Vec::new(), Vec::new()),
            Vec::new(),
            Vec::new(),
            empty.clone(),
        );
        let right = PartialPath::new(
            endpoint(seam, Vec::new(), Vec::new()),
            endpoint(node("empty-incomplete-right"), Vec::new(), Vec::new()),
            Vec::new(),
            Vec::new(),
            empty,
        );

        assert!(
            std::panic::catch_unwind(|| {
                let _ =
                    left.concatenate(&right, AlphaRenamingId::hash_bytes("empty-incomplete-use"));
            })
            .is_err()
        );
    }

    #[test]
    fn concatenation_rejects_different_endpoint_nodes() {
        let endpoint = |name| {
            EndpointSignature::new(
                node(name),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            )
        };
        let path = |start, end| {
            PartialPath::new(
                endpoint(start),
                endpoint(end),
                Vec::new(),
                Vec::new(),
                ResolutionCompletion::Complete,
            )
        };
        let left = path("left-start", "left-end");
        let right = path("right-start", "right-end");

        assert_eq!(
            left.concatenate(&right, AlphaRenamingId::hash_bytes("right-use")),
            Err(PathCompositionError::EndpointMismatch {
                left: node("left-end"),
                right: node("right-start"),
            })
        );
        assert_eq!(
            left.concatenate_with_poll(
                &right,
                AlphaRenamingId::hash_bytes("right-use"),
                &mut || false,
            ),
            Some(Err(PathCompositionError::EndpointMismatch {
                left: node("left-end"),
                right: node("right-start"),
            }))
        );
    }

    #[test]
    fn polled_path_construction_matches_public_semantics_and_cancels_inside_completion() {
        // The model calls the injected poll directly; no engine sampling is involved.
        const POLL_BUDGET: usize = 32;

        let start = endpoint(node("polled-construction-start"), Vec::new(), Vec::new());
        let end = endpoint(node("polled-construction-end"), Vec::new(), Vec::new());
        let reason =
            ResolutionIncompleteReason::UnsupportedSemantic(semantic("polled-construction-gap"));
        let completion = ResolutionCompletion::Incomplete(CompletionReasons::from(
            std::iter::repeat_n(reason, POLL_BUDGET + 1).collect::<Vec<_>>(),
        ));
        let expected = PartialPath::new(
            start.clone(),
            end.clone(),
            Vec::new(),
            Vec::new(),
            completion.clone(),
        );
        let actual = PartialPath::new_with_poll(
            start.clone(),
            end.clone(),
            Vec::new().into_boxed_slice(),
            Vec::new().into_boxed_slice(),
            completion.clone(),
            &mut || false,
        )
        .expect("uncancelled path construction completes");
        assert_eq!(actual, expected);

        let mut polls = 0_usize;
        assert!(
            PartialPath::new_with_poll(
                start,
                end,
                Vec::new().into_boxed_slice(),
                Vec::new().into_boxed_slice(),
                completion,
                &mut || {
                    polls += 1;
                    polls > POLL_BUDGET
                },
            )
            .is_none()
        );
        assert_eq!(polls, POLL_BUDGET + 1);
    }

    #[test]
    fn attached_scope_unification_propagates_through_the_whole_path() {
        let captured_tail = variable("captured-tail");
        let seam = node("scoped-seam");
        let captured_scope = node("captured-scope");
        let lexical_scope = node("lexical-scope");
        let left = PartialPath::new(
            EndpointSignature::new_scoped(
                node("left-start"),
                StackPattern::closed(vec![PartialScopedSymbol::scoped(
                    semantic("closure"),
                    StackPattern::open(Vec::new(), captured_tail),
                )]),
                StackPattern::open(Vec::new(), captured_tail),
            ),
            EndpointSignature::new_scoped(
                seam,
                StackPattern::closed(vec![PartialScopedSymbol::scoped(
                    semantic("member"),
                    StackPattern::open(vec![lexical_scope], captured_tail),
                )]),
                StackPattern::open(Vec::new(), captured_tail),
            ),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let right = PartialPath::new(
            EndpointSignature::new_scoped(
                seam,
                StackPattern::closed(vec![PartialScopedSymbol::scoped(
                    semantic("member"),
                    StackPattern::closed(vec![lexical_scope, captured_scope]),
                )]),
                StackPattern::closed(vec![captured_scope]),
            ),
            EndpointSignature::new(
                node("right-end"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );

        let joined = left
            .concatenate(&right, AlphaRenamingId::hash_bytes("right-use"))
            .expect("attached and top-level scopes share one substitution");

        assert_eq!(
            joined.start().symbols().fixed()[0].scopes(),
            Some(&StackPattern::closed(vec![captured_scope]))
        );
        assert_eq!(
            joined.start().scopes(),
            &StackPattern::closed(vec![captured_scope])
        );
    }

    #[test]
    fn scoped_and_unscoped_symbol_cells_do_not_unify() {
        let seam = node("seam");
        let endpoint = |scoped| {
            let symbol = if scoped {
                PartialScopedSymbol::scoped(
                    semantic("name"),
                    StackPattern::closed(vec![node("scope")]),
                )
            } else {
                PartialScopedSymbol::unscoped(semantic("name"))
            };
            EndpointSignature::new_scoped(
                seam,
                StackPattern::closed(vec![symbol]),
                StackPattern::closed(Vec::new()),
            )
        };
        let path = |start, end| {
            PartialPath::new(
                start,
                end,
                Vec::new(),
                Vec::new(),
                ResolutionCompletion::Complete,
            )
        };
        let left = path(
            EndpointSignature::new(
                node("start"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            endpoint(true),
        );
        let right = path(
            endpoint(false),
            EndpointSignature::new(
                node("end"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
        );

        assert_eq!(
            left.concatenate(&right, AlphaRenamingId::hash_bytes("right-use")),
            Err(PathCompositionError::SymbolStack(
                StackUnificationError::FixedCellMismatch { index: 0 }
            ))
        );
    }

    #[test]
    fn typed_frontier_canonicalizes_semantically_distinct_value_alternatives() {
        let first = semantic("first-type");
        let second = semantic("second-type");
        let runtime_first = ResolutionSlotValue::runtime(ResolutionTypeRef::new(first, 0), false);
        let addressable_first =
            ResolutionSlotValue::runtime(ResolutionTypeRef::new(first, 0), true);
        let pointer_second = ResolutionSlotValue::runtime(ResolutionTypeRef::new(second, 2), false);
        let type_object_second =
            ResolutionSlotValue::type_object(ResolutionTypeRef::new(second, 0));
        let state = TypedFrontierState::new(
            semantic("slot"),
            [
                pointer_second,
                addressable_first,
                runtime_first,
                type_object_second,
                runtime_first,
            ],
            ResolutionCompletion::Complete,
        );

        let mut expected = vec![
            runtime_first,
            addressable_first,
            pointer_second,
            type_object_second,
        ];
        expected.sort_unstable();
        assert_eq!(state.possible_values(), expected);
        assert_eq!(type_object_second.addressable(), None);
        assert_eq!(addressable_first.addressable(), Some(true));
        assert_eq!(pointer_second.ty().indirection(), 2);
        assert_eq!(pointer_second.ty().identity(), second);
    }
    fn alpha_renamed(path: &PartialPath, renaming: AlphaRenamingId) -> PartialPath {
        path.alpha_renamed_with_poll(renaming, &mut || false)
            .expect("live test alpha renaming completes")
    }

    fn stack_effect_alpha_key(path: &PartialPath) -> StackEffectAlphaKey {
        path.stack_effect_alpha_key_with_poll(&mut || false)
            .expect("live test alpha-key construction completes")
    }

    #[test]
    fn polled_path_clone_preserves_every_nested_structure() {
        let symbol_tail = variable("polled-clone-symbol-tail");
        let attached_tail = variable("polled-clone-attached-tail");
        let scope_tail = variable("polled-clone-scope-tail");
        let path = PartialPath::new(
            EndpointSignature::new_scoped(
                node("polled-clone-start"),
                StackPattern::open(
                    vec![PartialScopedSymbol::scoped(
                        semantic("polled-clone-symbol"),
                        StackPattern::open(
                            vec![node("polled-clone-captured-scope")],
                            attached_tail,
                        ),
                    )],
                    symbol_tail,
                ),
                StackPattern::open(vec![node("polled-clone-scope")], scope_tail),
            ),
            EndpointSignature::new(
                node("polled-clone-end"),
                StackPattern::open(vec![semantic("polled-clone-end-symbol")], symbol_tail),
                StackPattern::open(Vec::new(), scope_tail),
            ),
            [PrecedenceStep {
                tier: PrecedenceTier::OwnMember,
                ordinal: 7,
                semantic: semantic("polled-clone-precedence"),
            }],
            [
                WitnessStep::Node(node("polled-clone-witness")),
                WitnessStep::Candidate {
                    semantic: semantic("polled-clone-target"),
                    outcome: CandidateOutcome::Selected,
                },
            ],
            ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(semantic("polled-clone-gap-a")),
                ResolutionIncompleteReason::UnsupportedSemantic(semantic("polled-clone-gap-b")),
            ]),
        );
        let mut polls = 0_usize;

        let cloned = path
            .clone_with_poll(&mut || {
                polls += 1;
                false
            })
            .expect("an uncancelled structural clone completes");

        assert_eq!(cloned, path);
        assert!(polls > path.precedence().len() + path.witness().len());
    }

    #[test]
    fn polled_path_clone_and_composition_cancel_inside_one_large_path() {
        use super::super::engine::CANCELLATION_QUANTUM;

        let seam = node("polled-large-path-seam");
        let large = PartialPath::new(
            EndpointSignature::new(
                seam,
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            EndpointSignature::new(
                node("polled-large-path-end"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            Vec::new(),
            std::iter::repeat_n(
                WitnessStep::Node(node("polled-large-path-witness")),
                CANCELLATION_QUANTUM + 1,
            )
            .collect::<Vec<_>>(),
            ResolutionCompletion::Complete,
        );
        let left = PartialPath::new(
            EndpointSignature::new(
                node("polled-large-path-start"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            EndpointSignature::new(
                seam,
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let cancelled_after_quantum = |polls: &mut usize| {
            *polls += 1;
            *polls > CANCELLATION_QUANTUM
        };
        let mut clone_polls = 0_usize;
        let mut composition_polls = 0_usize;
        let mut canonicalization_polls = 0_usize;

        let expected_canonical = large.clone().canonicalized_observations();
        let actual_canonical = large
            .clone()
            .canonicalized_observations_with_poll(&mut || false)
            .expect("uncancelled canonicalization completes");
        assert_eq!(actual_canonical, expected_canonical);

        assert!(
            large
                .clone_with_poll(&mut || cancelled_after_quantum(&mut clone_polls))
                .is_none(),
            "a cancelled clone must not expose a structural prefix"
        );
        assert!(
            left.concatenate_with_poll(
                &large,
                AlphaRenamingId::hash_bytes("polled-large-path-use"),
                &mut || cancelled_after_quantum(&mut composition_polls),
            )
            .is_none(),
            "cancellation is distinct from a stack-unification failure"
        );
        assert!(
            large
                .canonicalized_observations_with_poll(&mut || {
                    cancelled_after_quantum(&mut canonicalization_polls)
                })
                .is_none(),
            "cancelled observation canonicalization must not expose a path prefix"
        );
        assert_eq!(clone_polls, CANCELLATION_QUANTUM + 1);
        assert_eq!(composition_polls, CANCELLATION_QUANTUM + 1);
        assert_eq!(canonicalization_polls, CANCELLATION_QUANTUM + 1);
    }

    #[test]
    fn stack_effect_key_preserves_nested_scope_variable_aliasing() {
        let make_path = |attached_tail, top_tail| {
            PartialPath::new(
                EndpointSignature::new_scoped(
                    node("start"),
                    StackPattern::closed(vec![PartialScopedSymbol::scoped(
                        semantic("name"),
                        StackPattern::open(vec![node("scope")], attached_tail),
                    )]),
                    StackPattern::open(Vec::new(), top_tail),
                ),
                EndpointSignature::new_scoped(
                    node("end"),
                    StackPattern::open(Vec::new(), variable("symbol-tail")),
                    StackPattern::open(Vec::new(), top_tail),
                ),
                Vec::new(),
                Vec::new(),
                ResolutionCompletion::Complete,
            )
        };
        let aliased = make_path(variable("scope-a"), variable("scope-a"));
        let alpha_equivalent = make_path(variable("scope-b"), variable("scope-b"));
        let split = make_path(variable("scope-c"), variable("scope-d"));

        assert_eq!(
            stack_effect_alpha_key(&aliased),
            stack_effect_alpha_key(&alpha_equivalent)
        );
        assert_ne!(
            stack_effect_alpha_key(&aliased),
            stack_effect_alpha_key(&split)
        );
        assert_eq!(
            stack_effect_alpha_key(&aliased),
            stack_effect_alpha_key(&alpha_renamed(
                &aliased,
                AlphaRenamingId::hash_bytes("fresh-use"),
            ))
        );
    }
}
