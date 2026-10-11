//! Stage 2 of the composition: evaluate the taint classes forward along each
//! retained path with the solver's edge-function algebra, and intersect the
//! reached classes with the sink's accepted classes.

use crate::value_flow::ValueFlowSinkId;

use super::graph::{ComposedSourceId, Hop, HopQuality};
use super::provider::BoundSource;
use super::search::SourceSinkPair;
use crate::taint::{
    SourceClassId, TaintAnalysisPlan, TaintClassSet, TaintEdgeFunction, TaintUniverse,
};

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
/// transforms change labels; every other hop, the unmodeled-call fallback
/// included, is the identity.
pub(super) fn hop_function(hop: &Hop, universe: &TaintUniverse) -> TaintEdgeFunction {
    match hop {
        Hop::Model { moved, removed, .. } => {
            let mut function = TaintEdgeFunction::identity(universe);
            if let Some(moved) = moved {
                let every = universe
                    .class_set(universe.classes())
                    .expect("a universe's own classes form a set");
                function = function.compose(&TaintEdgeFunction::kill(&every.subtract(moved)));
            }
            function.compose(&TaintEdgeFunction::kill(removed))
        }
        Hop::Sanitizer {
            removed,
            proven: true,
            ..
        } => TaintEdgeFunction::kill(removed),
        Hop::Transform { function, .. } => function.clone(),
        Hop::Sanitizer { proven: false, .. }
        | Hop::Interior { .. }
        | Hop::Stored { .. }
        | Hop::Callee { .. }
        | Hop::Caller { .. }
        | Hop::Closure { .. }
        | Hop::Unmodeled { .. } => TaintEdgeFunction::identity(universe),
    }
}

/// The label function of a run of hops, in path order.
pub(super) fn hops_function(hops: &[Hop], universe: &TaintUniverse) -> TaintEdgeFunction {
    hops.iter()
        .fold(TaintEdgeFunction::identity(universe), |function, hop| {
            function.compose(&hop_function(hop, universe))
        })
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
            let function = hops_function(hops, universe);
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
