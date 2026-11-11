//! Stage 2 of the composition: evaluate the taint classes forward along each
//! retained path with the solver's edge-function algebra, and intersect the
//! reached classes with the sink's accepted classes.

use std::fmt::Debug;
use std::hash::Hash;

use crate::hash::HashMap;
use crate::value_flow::ValueFlowSinkId;

use super::graph::{ComposedSourceId, Hop, HopQuality};
use super::provider::BoundSource;
use super::search::SourceSinkPair;
use crate::taint::{
    SourceClassId, TaintAnalysisPlan, TaintClassSet, TaintEdgeFunction, TaintUniverse,
};

/// The label algebra a composition client supplies. The search keys every
/// path by the label function from its node to its root and never looks at
/// labels otherwise, so it needs only these operations: a `Fact` is a set of
/// labels a value carries, and a `Function` maps the facts entering a path to
/// the facts leaving it.
pub trait ComposeLabels {
    type Fact: Clone + Eq + Hash + Debug;
    type Function: Clone + Eq + Hash + Debug;

    fn identity(&self) -> Self::Function;
    /// `first`, then `second`, in path order.
    fn then(&self, first: &Self::Function, second: &Self::Function) -> Self::Function;
    fn apply(&self, function: &Self::Function, fact: &Self::Fact) -> Self::Fact;
    fn intersects(&self, left: &Self::Fact, right: &Self::Fact) -> bool;
}

/// The taint label algebra: classes of the plan's universe and the solver's
/// edge functions.
#[derive(Debug, Clone, Copy)]
pub struct TaintLabels<'u> {
    universe: &'u TaintUniverse,
}

impl<'u> TaintLabels<'u> {
    pub const fn new(universe: &'u TaintUniverse) -> Self {
        Self { universe }
    }
}

impl ComposeLabels for TaintLabels<'_> {
    type Fact = TaintClassSet;
    type Function = TaintEdgeFunction;

    fn identity(&self) -> TaintEdgeFunction {
        TaintEdgeFunction::identity(self.universe)
    }

    fn then(&self, first: &TaintEdgeFunction, second: &TaintEdgeFunction) -> TaintEdgeFunction {
        first.compose(second)
    }

    fn apply(&self, function: &TaintEdgeFunction, fact: &TaintClassSet) -> TaintClassSet {
        function.apply(fact)
    }

    fn intersects(&self, left: &TaintClassSet, right: &TaintClassSet) -> bool {
        left.intersects(right)
    }
}

/// A label function interned in one search's [`LabelFunctions`]. Equal
/// functions get equal ids, so an id keys a path exactly as its function
/// would.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LabelFunctionId(u32);

impl LabelFunctionId {
    /// Every table interns the identity first.
    pub const IDENTITY: Self = Self(0);
}

/// The label functions of one search, interned so that path keys and hops
/// carry a small id instead of a function. It lives as long as the search
/// that fills it and is handed to the label stage with the search's pairs.
#[derive(Debug, Clone)]
pub struct LabelFunctions<L: ComposeLabels> {
    labels: L,
    functions: Vec<L::Function>,
    ids: HashMap<L::Function, LabelFunctionId>,
    then: HashMap<(LabelFunctionId, LabelFunctionId), LabelFunctionId>,
}

impl<L: ComposeLabels> LabelFunctions<L> {
    pub fn new(labels: L) -> Self {
        let mut table = Self {
            functions: Vec::new(),
            ids: HashMap::default(),
            then: HashMap::default(),
            labels,
        };
        let identity = table.labels.identity();
        assert_eq!(table.intern(identity), LabelFunctionId::IDENTITY);
        table
    }

    pub const fn labels(&self) -> &L {
        &self.labels
    }

    pub fn intern(&mut self, function: L::Function) -> LabelFunctionId {
        if let Some(&id) = self.ids.get(&function) {
            return id;
        }
        let id = LabelFunctionId(
            u32::try_from(self.functions.len()).expect("a search's label functions fit u32"),
        );
        self.functions.push(function.clone());
        self.ids.insert(function, id);
        id
    }

    pub fn function(&self, id: LabelFunctionId) -> &L::Function {
        &self.functions[usize::try_from(id.0).expect("a label function id fits usize")]
    }

    /// `first`, then `second`.
    pub fn then(&mut self, first: LabelFunctionId, second: LabelFunctionId) -> LabelFunctionId {
        if first == LabelFunctionId::IDENTITY {
            return second;
        }
        if second == LabelFunctionId::IDENTITY {
            return first;
        }
        if let Some(&id) = self.then.get(&(first, second)) {
            return id;
        }
        let composed = self
            .labels
            .then(self.function(first), self.function(second));
        let id = self.intern(composed);
        self.then.insert((first, second), id);
        id
    }

    /// The label function of a run of hops, in path order.
    pub fn hops(&mut self, hops: &[Hop]) -> LabelFunctionId {
        hops.iter()
            .fold(LabelFunctionId::IDENTITY, |function, hop| {
                self.then(function, hop_function(hop))
            })
    }

    /// The same, for a reader that cannot intern: the label stage evaluates
    /// retained paths after the search has finished.
    pub fn hops_value(&self, hops: &[Hop]) -> L::Function {
        hops.iter().fold(self.labels.identity(), |function, hop| {
            self.labels
                .then(&function, self.function(hop_function(hop)))
        })
    }
}

/// The classes named by stable policy labels. A label absent from the run's
/// universe cannot appear in any fact, so it is skipped.
pub(super) fn label_classes(universe: &TaintUniverse, labels: &[Box<str>]) -> TaintClassSet {
    let mut classes = universe.empty_set();
    for label in labels {
        if let Ok(class) = SourceClassId::new(label.as_ref())
            && let Some(id) = universe.class_id(&class)
        {
            classes.insert_dense(id);
        }
    }
    classes
}

/// The label function of one hop. Only models, proven sanitizers and
/// transforms and projected procedure flows can change labels; all other hops,
/// including the unmodeled-call fallback, are the identity.
pub(super) const fn hop_function(hop: &Hop) -> LabelFunctionId {
    match hop {
        Hop::Invocation { function, .. }
        | Hop::Interior { function, .. }
        | Hop::Stored { function, .. }
        | Hop::Model { function, .. }
        | Hop::Caller { function, .. }
        | Hop::Callee { function, .. }
        | Hop::CallHandoff { function, .. }
        | Hop::Sanitizer { function, .. }
        | Hop::Transform { function, .. } => *function,
        Hop::Closure { .. } | Hop::Unmodeled { .. } | Hop::Store { .. } => {
            LabelFunctionId::IDENTITY
        }
    }
}

/// One retained path whose reached classes meet the sink's accepted classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LabeledPath {
    pub(super) source: ComposedSourceId,
    pub(super) sink: ValueFlowSinkId,
    pub(super) hops: Vec<Hop>,
    /// Source classes that reach the sink as an accepted class.
    pub(super) contributed: TaintClassSet,
    /// Accepted classes observed at the sink.
    pub(super) reached: TaintClassSet,
    /// The best quality of the paths that share this path's label function.
    pub(super) quality: HopQuality,
}

/// Evaluate every retained path of every pair. A path whose reached classes
/// miss the sink's accepted classes is not kept. `sources` is the search's
/// source table.
pub(super) fn evaluate_pairs(
    plan: &TaintAnalysisPlan,
    functions: &LabelFunctions<TaintLabels<'_>>,
    sources: &[BoundSource],
    pairs: &[SourceSinkPair],
) -> Vec<LabeledPath> {
    let universe = plan.universe();
    let mut labeled = Vec::new();
    for pair in pairs {
        let classes = &sources[pair.source.index()].classes;
        let accepted = plan
            .sink(pair.sink)
            .expect("a pair names a sink of its plan")
            .accepted();
        for (hops, quality) in &pair.paths {
            let function = functions.hops_value(hops);
            let reached = function.apply(classes).intersection(accepted);
            if reached.is_empty() {
                continue;
            }
            let mut contributed = universe.empty_set();
            for class in classes.iter_dense() {
                let mut single = universe.empty_set();
                single.insert_dense(class);
                if function.apply(&single).intersects(accepted) {
                    contributed.insert_dense(class);
                }
            }
            labeled.push(LabeledPath {
                source: pair.source,
                sink: pair.sink,
                hops: hops.clone(),
                contributed,
                reached,
                quality: *quality,
            });
        }
    }
    labeled
}
