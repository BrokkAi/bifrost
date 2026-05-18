use crate::hash::{HashMap, HashSet};
use std::hash::Hash;

const DEFAULT_MAX_TARGETS_PER_SYMBOL: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalInferenceConfig {
    pub max_targets_per_symbol: usize,
}

impl Default for LocalInferenceConfig {
    fn default() -> Self {
        Self {
            max_targets_per_symbol: DEFAULT_MAX_TARGETS_PER_SYMBOL,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolResolution<T: Eq + Hash> {
    Unknown,
    Ambiguous,
    Precise(HashSet<T>),
}

impl<T> SymbolResolution<T>
where
    T: Eq + Hash,
{
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }

    pub fn is_ambiguous(&self) -> bool {
        matches!(self, Self::Ambiguous)
    }

    pub fn as_precise(&self) -> Option<&HashSet<T>> {
        match self {
            Self::Precise(targets) => Some(targets),
            Self::Unknown | Self::Ambiguous => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalBindingsSnapshot<T: Eq + Hash> {
    shadows: HashSet<String>,
    bindings: HashMap<String, SymbolResolution<T>>,
}

impl<T> LocalBindingsSnapshot<T>
where
    T: Eq + Hash,
{
    pub fn is_shadowed(&self, symbol: &str) -> bool {
        self.shadows.contains(symbol)
    }

    pub fn from_parts(
        shadows: HashSet<String>,
        bindings: HashMap<String, SymbolResolution<T>>,
    ) -> Self {
        Self { shadows, bindings }
    }

    pub fn resolution_for(&self, symbol: &str) -> SymbolResolution<T>
    where
        T: Clone,
    {
        self.bindings
            .get(symbol)
            .cloned()
            .unwrap_or(SymbolResolution::Unknown)
    }

    pub fn matching_symbols<F>(&self, mut predicate: F) -> HashSet<String>
    where
        F: FnMut(&T) -> bool,
    {
        self.bindings
            .iter()
            .filter_map(|(symbol, resolution)| match resolution {
                SymbolResolution::Precise(targets) if targets.iter().any(&mut predicate) => {
                    Some(symbol.clone())
                }
                SymbolResolution::Unknown
                | SymbolResolution::Ambiguous
                | SymbolResolution::Precise(_) => None,
            })
            .collect()
    }

    pub fn cloned_bindings(&self) -> HashMap<String, SymbolResolution<T>>
    where
        T: Clone,
    {
        self.bindings.clone()
    }

    pub fn cloned_shadows(&self) -> HashSet<String> {
        self.shadows.clone()
    }
}

#[derive(Debug, Clone)]
pub struct LocalInferenceEngine<T: Eq + Hash> {
    config: LocalInferenceConfig,
    scopes: Vec<ScopeState<T>>,
}

impl<T> Default for LocalInferenceEngine<T>
where
    T: Clone + Eq + Hash,
{
    fn default() -> Self {
        Self::new(LocalInferenceConfig::default())
    }
}

impl<T> LocalInferenceEngine<T>
where
    T: Clone + Eq + Hash,
{
    pub fn new(config: LocalInferenceConfig) -> Self {
        Self {
            config,
            scopes: vec![ScopeState::default()],
        }
    }

    pub fn enter_scope(&mut self) {
        self.scopes.push(ScopeState::default());
    }

    pub fn exit_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    pub fn declare_shadow(&mut self, symbol: impl Into<String>) {
        let symbol = symbol.into();
        let scope = self.current_scope_mut();
        scope.shadows.insert(symbol.clone());
        scope.bindings.remove(&symbol);
    }

    pub fn seed_symbol(&mut self, symbol: impl Into<String>, target: T) {
        self.seed_symbol_many(symbol, [target]);
    }

    pub fn seed_symbol_many<I>(&mut self, symbol: impl Into<String>, targets: I)
    where
        I: IntoIterator<Item = T>,
    {
        let symbol = symbol.into();
        let max_targets_per_symbol = self.config.max_targets_per_symbol;
        let resolution = bounded_resolution(targets.into_iter().collect(), max_targets_per_symbol);
        let scope = self.current_scope_mut();
        scope.shadows.insert(symbol.clone());
        scope.bindings.insert(symbol, resolution);
    }

    pub fn alias_symbol(&mut self, symbol: impl Into<String>, source_symbol: &str) {
        let symbol = symbol.into();
        let source_resolution = self.resolve_symbol(source_symbol);
        let scope = self.current_scope_mut();
        scope.shadows.insert(symbol.clone());
        scope.bindings.insert(symbol, source_resolution);
    }

    pub fn resolve_symbol(&self, symbol: &str) -> SymbolResolution<T> {
        for scope in self.scopes.iter().rev() {
            if let Some(resolution) = scope.bindings.get(symbol) {
                return resolution.clone();
            }
            if scope.shadows.contains(symbol) {
                return SymbolResolution::Unknown;
            }
        }
        SymbolResolution::Unknown
    }

    pub fn is_shadowed(&self, symbol: &str) -> bool {
        self.scopes
            .iter()
            .rev()
            .any(|scope| scope.shadows.contains(symbol))
    }

    pub fn snapshot(&self) -> LocalBindingsSnapshot<T> {
        let mut shadows = HashSet::default();
        let mut bindings = HashMap::default();
        for scope in &self.scopes {
            for symbol in &scope.shadows {
                shadows.insert(symbol.clone());
            }
            for (symbol, resolution) in &scope.bindings {
                bindings.insert(symbol.clone(), resolution.clone());
            }
        }
        LocalBindingsSnapshot { shadows, bindings }
    }
}

#[derive(Debug, Clone)]
struct ScopeState<T: Eq + Hash> {
    shadows: HashSet<String>,
    bindings: HashMap<String, SymbolResolution<T>>,
}

impl<T> Default for ScopeState<T>
where
    T: Eq + Hash,
{
    fn default() -> Self {
        Self {
            shadows: HashSet::default(),
            bindings: HashMap::default(),
        }
    }
}

impl<T> LocalInferenceEngine<T>
where
    T: Eq + Hash,
{
    fn current_scope_mut(&mut self) -> &mut ScopeState<T> {
        self.scopes
            .last_mut()
            .expect("local inference engine always keeps a root scope")
    }
}

fn bounded_resolution<T>(targets: HashSet<T>, max_targets_per_symbol: usize) -> SymbolResolution<T>
where
    T: Eq + Hash,
{
    if targets.is_empty() {
        SymbolResolution::Unknown
    } else if targets.len() > max_targets_per_symbol {
        SymbolResolution::Ambiguous
    } else {
        SymbolResolution::Precise(targets)
    }
}
