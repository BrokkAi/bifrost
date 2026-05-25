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
    declared: HashSet<String>,
    bindings: HashMap<String, SymbolResolution<T>>,
}

impl<T> LocalBindingsSnapshot<T>
where
    T: Eq + Hash,
{
    fn visible_binding(&self, symbol: &str) -> Option<&SymbolResolution<T>> {
        self.bindings.get(symbol)
    }

    pub fn is_shadowed(&self, symbol: &str) -> bool {
        self.declared.contains(symbol)
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

    pub fn filtered_visible_bindings<F>(&self, mut predicate: F) -> Self
    where
        T: Clone,
        F: FnMut(&str, &SymbolResolution<T>) -> bool,
    {
        let bindings: HashMap<String, SymbolResolution<T>> = self
            .bindings
            .iter()
            .filter(|(symbol, resolution)| predicate(symbol.as_str(), resolution))
            .map(|(symbol, resolution)| (symbol.clone(), resolution.clone()))
            .collect();
        Self {
            declared: bindings.keys().cloned().collect(),
            bindings,
        }
    }

    pub fn merged_with_visible(&self, other: &Self) -> Self
    where
        T: Clone,
    {
        let mut bindings = self.bindings.clone();
        for (symbol, resolution) in &other.bindings {
            bindings.insert(symbol.clone(), resolution.clone());
        }
        Self {
            declared: self
                .declared
                .iter()
                .cloned()
                .chain(other.declared.iter().cloned())
                .collect(),
            bindings,
        }
    }

    pub fn resolution_for(&self, symbol: &str) -> SymbolResolution<T>
    where
        T: Clone,
    {
        self.visible_binding(symbol)
            .cloned()
            .unwrap_or(SymbolResolution::Unknown)
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

    pub fn apply_aliases_until_stable<I>(&mut self, aliases: I)
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let aliases: Vec<_> = aliases.into_iter().collect();
        loop {
            let mut changed = false;
            for (lhs, rhs) in &aliases {
                if self.resolve_symbol(lhs).is_unknown() && !self.resolve_symbol(rhs).is_unknown() {
                    self.alias_symbol(lhs.clone(), rhs);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
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
        let mut declared = HashSet::default();
        let mut bindings = HashMap::default();
        for scope in self.scopes.iter().rev() {
            for symbol in &scope.shadows {
                if !declared.insert(symbol.clone()) {
                    continue;
                }
                if let Some(resolution) = scope.bindings.get(symbol) {
                    bindings.insert(symbol.clone(), resolution.clone());
                }
            }
        }
        LocalBindingsSnapshot { declared, bindings }
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
