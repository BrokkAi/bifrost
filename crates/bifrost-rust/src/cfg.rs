//! Cfg activation over a selected cfg atom set. Source producers never consult
//! this module.
//!
//! An atom set spells each enabled cfg as source predicates do: `name`, or
//! `name = "value"`. It comes from `cargo_config`: the build target's values,
//! `test`, `debug_assertions`, and the `--cfg` rustflags Cargo configuration
//! sets. Persisted inventories may also carry the internal completeness
//! annotation below when retained manifests cannot prove the full feature set.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::OnceLock;

use brokk_bifrost_core::analyzer::rust_facts::{RustCfgCondition, RustCfgInstruction};

use crate::selected_context::{RustCallerTargetProfile, RustSelectedActivation};

/// Internal annotation in a persisted cfg atom set: retained Cargo manifests
/// do not establish the complete feature set. When present, an absent
/// `feature = "..."` atom must evaluate to Unknown, not Inactive; proven enabled
/// features remain Active. This is metadata, not a rustc cfg flag.
///
/// Readers of this contract are `crate_activation`, `crate_site_cfg_activation`,
/// `crate_activation_under_site_cfg` and `crate_cfg_literal_activation`, through
/// `absent_crate_atom`. A site query can then choose an explicit satisfying
/// assignment; that assumption does not prove unconditional activation.
///
/// The SQLite functions `cr_cfg` and `cr_authority_cfg`, registered in
/// `crates/bifrost-store/src/analyzer/store/rust_crates.rs`, must preserve the
/// annotation when decoding cfg atom JSON and delegate to `crate_activation`.
/// This covers SQL readers in `rust_crate_point_unindexed_scope.sql`,
/// `rust_crate_point_export.sql`, `rust_crate_published_macro_prelude.sql`,
/// `rust_demand/rows.rs` and `rust_crate_context.rs` under `resolution_operation`.
/// Rust readers in that directory's `rust_crate_access.rs` and
/// `rust_reverse_rows.rs` must likewise preserve it when calling these shared
/// evaluators. Their detached evaluators already leave absent features Unknown.
/// Topology persistence, `rust_crate_context.rs` and `rust_unit_summaries.rs`
/// transport cfg atom JSON intact, including this annotation. Do not replace
/// these evaluations with a raw feature-membership test.
pub(crate) const INCOMPLETE_FEATURES_ATOM: &str = "bifrost_incomplete_features";

fn absent_crate_atom(atoms: &BTreeSet<String>, name: &str) -> RustSelectedActivation {
    if name.starts_with("feature = ") && !atoms.contains(INCOMPLETE_FEATURES_ATOM) {
        RustSelectedActivation::Inactive
    } else {
        RustSelectedActivation::Unknown
    }
}

/// The cfg keys whose complete value set a described target fixes, so a value
/// the set does not hold is false. Every other key stays unknown when absent,
/// because a build script can set it.
const TARGET_CFG_KEYS: [&str; 6] = [
    "target_os",
    "target_arch",
    "target_family",
    "target_pointer_width",
    "target_endian",
    "target_has_atomic",
];

/// Whether an atom set describes its build target, so that a target value or
/// a bare `unix` or `windows` it does not hold is false. A set from a target
/// rustc does not know, or from several targets, has no target values, and
/// every described target has exactly one endianness.
pub(crate) fn describes_target(contains: impl Fn(&str) -> bool) -> bool {
    contains("target_endian = \"little\"") || contains("target_endian = \"big\"")
}

/// The cfg set of a build with no Cargo configuration: the host's.
pub fn default_cfg_atoms() -> BTreeSet<String> {
    host_cfg_atoms().clone()
}

fn host_cfg_atoms() -> &'static BTreeSet<String> {
    static HOST: OnceLock<BTreeSet<String>> = OnceLock::new();
    HOST.get_or_init(|| {
        crate::cargo_config::RustCargoConfiguration::default().cfg_atoms(Path::new(""))
    })
}

/// A selected profile's activation. Profiles are host profiles: the host set
/// holds whatever the profile's own atoms and features do not.
pub(crate) fn activation(
    profile: &RustCallerTargetProfile,
    condition: &RustCfgCondition,
) -> RustSelectedActivation {
    let host = host_cfg_atoms();
    evaluate(
        condition,
        |name| host.contains(name) || profile.cfg_atoms.contains(name),
        |name| {
            if profile
                .features
                .iter()
                .any(|feature| name == format!("feature = {feature:?}"))
            {
                RustSelectedActivation::Active
            } else {
                RustSelectedActivation::Unknown
            }
        },
    )
}

/// A detached source has no complete Cargo feature inventory. Unknown feature
/// atoms remain unknown, while selected host atoms retain their exact values.
///
/// This is the reading the crate-set policy and the reverse take, because both
/// certify absence over files whose Cargo target bifrost may not have found.
/// A point request answers under the selected configuration instead and uses
/// `crate_activation` below for every root, detached included.
pub fn detached_activation(
    atoms: &BTreeSet<String>,
    condition: &RustCfgCondition,
) -> RustSelectedActivation {
    evaluate(
        condition,
        |name| atoms.contains(name),
        |_| RustSelectedActivation::Unknown,
    )
}

/// A Cargo feature set: absent features are false when its inventory is
/// complete, and unknown when it carries the incomplete-feature annotation.
/// Custom atoms without an inventory remain unknown. No crate state is retained.
pub fn crate_activation(
    atoms: &BTreeSet<String>,
    condition: &RustCfgCondition,
) -> RustSelectedActivation {
    evaluate(
        condition,
        |name| atoms.contains(name),
        |name| absent_crate_atom(atoms, name),
    )
}

/// A satisfying assignment for the undecidable literals in one reference
/// site's effective cfg condition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustCfgSiteAssignment {
    assumptions: CfgAssumptions,
}

/// Whether a site cfg can hold under the selected atoms, and one assignment
/// that makes it hold when undecidable literals are present.
pub fn crate_site_cfg_activation(
    atoms: &BTreeSet<String>,
    condition: &RustCfgCondition,
) -> (RustSelectedActivation, bool, Option<RustCfgSiteAssignment>) {
    site_cfg_activation(
        condition,
        |literal| crate_cfg_literal_activation(atoms, literal),
        |name| atoms.contains(name),
        |name| absent_crate_atom(atoms, name),
    )
}

/// Detached sources do not have a complete Cargo feature inventory.
pub fn detached_site_cfg_activation(
    atoms: &BTreeSet<String>,
    condition: &RustCfgCondition,
) -> (RustSelectedActivation, bool, Option<RustCfgSiteAssignment>) {
    site_cfg_activation(
        condition,
        |literal| detached_cfg_literal_activation(atoms, literal),
        |name| atoms.contains(name),
        |_| RustSelectedActivation::Unknown,
    )
}

/// Evaluate a candidate condition in the world selected for its reference
/// site's cfg predicate. Only the site's undecidable literals are overridden.
pub fn crate_activation_under_site_cfg(
    atoms: &BTreeSet<String>,
    condition: &RustCfgCondition,
    assignment: Option<&RustCfgSiteAssignment>,
) -> RustSelectedActivation {
    let assumptions = assignment.map_or(&[][..], |assignment| assignment.assumptions.as_slice());
    evaluate_with_assumptions(
        condition,
        |name| atoms.contains(name),
        |name| absent_crate_atom(atoms, name),
        assumptions,
    )
}

/// Evaluate a candidate from a detached source under a selected site cfg
/// assignment. Unrelated absent literals remain unknown.
pub fn detached_activation_under_site_cfg(
    atoms: &BTreeSet<String>,
    condition: &RustCfgCondition,
    assignment: Option<&RustCfgSiteAssignment>,
) -> RustSelectedActivation {
    let assumptions = assignment.map_or(&[][..], |assignment| assignment.assumptions.as_slice());
    evaluate_with_assumptions(
        condition,
        |name| atoms.contains(name),
        |_| RustSelectedActivation::Unknown,
        assumptions,
    )
}

/// Evaluate `condition` over the atom set `contains` answers for. An absent
/// `test` or `debug_assertions` is false, and so is an absent target value
/// when the set describes its target. `absent` decides every other atom and
/// key-value literal the set does not hold.
fn evaluate(
    condition: &RustCfgCondition,
    contains: impl Fn(&str) -> bool,
    absent: impl Fn(&str) -> RustSelectedActivation,
) -> RustSelectedActivation {
    evaluate_with_assumptions(condition, contains, absent, &[])
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum CfgLiteral {
    Atom(String),
    KeyValue { key: String, value: String },
}

/// Each value is the assumed truth of that exact literal.
type CfgAssumptions = Vec<(CfgLiteral, Option<bool>)>;

#[derive(Clone, Debug)]
enum CfgFormulaNode {
    Constant(bool),
    Literal(usize),
    Not(usize),
    All(Vec<usize>),
    Any(Vec<usize>),
}

#[derive(Default)]
struct CfgFormula {
    nodes: Vec<CfgFormulaNode>,
    undecidable: Vec<CfgLiteral>,
    undecidable_ids: HashMap<CfgLiteral, usize>,
}

impl CfgFormula {
    fn constant(&mut self, value: bool) -> usize {
        self.push(CfgFormulaNode::Constant(value))
    }

    fn literal(&mut self, literal: CfgLiteral, activation: RustSelectedActivation) -> usize {
        match activation {
            RustSelectedActivation::Active => self.constant(true),
            RustSelectedActivation::Inactive => self.constant(false),
            RustSelectedActivation::Unknown => {
                let variable = if let Some(variable) = self.undecidable_ids.get(&literal) {
                    *variable
                } else {
                    let variable = self.undecidable.len();
                    self.undecidable.push(literal.clone());
                    self.undecidable_ids.insert(literal, variable);
                    variable
                };
                self.push(CfgFormulaNode::Literal(variable))
            }
        }
    }

    fn negate(&mut self, child: usize) -> usize {
        match &self.nodes[child] {
            CfgFormulaNode::Constant(value) => self.constant(!value),
            CfgFormulaNode::Not(grandchild) => *grandchild,
            _ => self.push(CfgFormulaNode::Not(child)),
        }
    }

    fn all(&mut self, children: Vec<usize>) -> usize {
        self.combine(children, true)
    }

    fn any(&mut self, children: Vec<usize>) -> usize {
        self.combine(children, false)
    }

    fn combine(&mut self, children: Vec<usize>, conjunction: bool) -> usize {
        let mut residual = Vec::with_capacity(children.len());
        for child in children {
            match &self.nodes[child] {
                CfgFormulaNode::Constant(value) if *value != conjunction => {
                    return self.constant(!conjunction);
                }
                CfgFormulaNode::Constant(_) => {}
                _ => residual.push(child),
            }
        }
        match residual.len() {
            0 => self.constant(conjunction),
            1 => residual[0],
            _ if conjunction => self.push(CfgFormulaNode::All(residual)),
            _ => self.push(CfgFormulaNode::Any(residual)),
        }
    }

    fn push(&mut self, node: CfgFormulaNode) -> usize {
        let id = self.nodes.len();
        self.nodes.push(node);
        id
    }
}

fn site_cfg_activation(
    condition: &RustCfgCondition,
    literal_activation: impl Fn(&CfgLiteral) -> RustSelectedActivation,
    contains: impl Fn(&str) -> bool,
    absent: impl Fn(&str) -> RustSelectedActivation,
) -> (RustSelectedActivation, bool, Option<RustCfgSiteAssignment>) {
    let Some((formula, root)) = cfg_formula(condition, &literal_activation) else {
        return (RustSelectedActivation::Unknown, false, None);
    };

    if formula.undecidable.is_empty() {
        return (
            evaluate_with_assumptions(condition, &contains, &absent, &[]),
            false,
            None,
        );
    }

    let Some(values) = cfg_formula_satisfying_assignment(&formula, root) else {
        return (RustSelectedActivation::Inactive, false, None);
    };
    let assumptions = formula
        .undecidable
        .into_iter()
        .zip(values)
        .map(|(literal, value)| (literal, Some(value)))
        .collect();
    (
        RustSelectedActivation::Active,
        true,
        Some(RustCfgSiteAssignment { assumptions }),
    )
}

fn cfg_formula(
    condition: &RustCfgCondition,
    literal_activation: impl Fn(&CfgLiteral) -> RustSelectedActivation,
) -> Option<(CfgFormula, usize)> {
    let mut formula = CfgFormula::default();
    let mut stack = Vec::new();
    match condition {
        RustCfgCondition::Always => {
            let root = formula.constant(true);
            return Some((formula, root));
        }
        RustCfgCondition::Atom(name) => {
            let literal = CfgLiteral::Atom(name.clone());
            stack.push(formula.literal(literal.clone(), literal_activation(&literal)));
        }
        RustCfgCondition::NotAtom(name) => {
            let literal = CfgLiteral::Atom(name.clone());
            let child = formula.literal(literal.clone(), literal_activation(&literal));
            stack.push(formula.negate(child));
        }
        RustCfgCondition::Unknown => return None,
        RustCfgCondition::Expression(instructions) => {
            for instruction in instructions.iter() {
                match instruction {
                    RustCfgInstruction::Atom(name) => {
                        let literal = CfgLiteral::Atom(name.clone());
                        stack.push(formula.literal(literal.clone(), literal_activation(&literal)));
                    }
                    RustCfgInstruction::KeyValue { key, value } => {
                        let literal = CfgLiteral::KeyValue {
                            key: key.clone(),
                            value: value.clone(),
                        };
                        stack.push(formula.literal(literal.clone(), literal_activation(&literal)));
                    }
                    RustCfgInstruction::Unknown => return None,
                    RustCfgInstruction::Not => {
                        let child = stack.pop().expect("cfg negation has an operand");
                        stack.push(formula.negate(child));
                    }
                    RustCfgInstruction::All(count) | RustCfgInstruction::Any(count) => {
                        assert!(stack.len() >= *count, "cfg operator has its operands");
                        let children = stack.split_off(stack.len() - *count);
                        let combined = match instruction {
                            RustCfgInstruction::All(_) => formula.all(children),
                            RustCfgInstruction::Any(_) => formula.any(children),
                            _ => unreachable!("matched cfg operator"),
                        };
                        stack.push(combined);
                    }
                }
            }
        }
    }
    assert_eq!(stack.len(), 1, "cfg expression has exactly one result");
    Some((formula, stack.pop().expect("cfg expression result")))
}

fn cfg_formula_satisfying_assignment(formula: &CfgFormula, root: usize) -> Option<Vec<bool>> {
    let mut reachable = vec![false; formula.nodes.len()];
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if std::mem::replace(&mut reachable[node], true) {
            continue;
        }
        match &formula.nodes[node] {
            CfgFormulaNode::Constant(_) | CfgFormulaNode::Literal(_) => {}
            CfgFormulaNode::Not(child) => pending.push(*child),
            CfgFormulaNode::All(children) | CfgFormulaNode::Any(children) => {
                pending.extend(children.iter().copied());
            }
        }
    }

    let mut clauses = Vec::new();
    let mut values = Vec::with_capacity(formula.nodes.len());
    let mut variable_count = formula.undecidable.len();
    for (id, node) in formula.nodes.iter().enumerate() {
        if !reachable[id] {
            values.push(CfgSatValue::Constant(false));
            continue;
        }
        let value = match node {
            CfgFormulaNode::Constant(value) => CfgSatValue::Constant(*value),
            CfgFormulaNode::Literal(variable) => {
                CfgSatValue::Literal(cfg_sat_literal(*variable, true))
            }
            CfgFormulaNode::Not(child) => match values[*child] {
                CfgSatValue::Constant(value) => CfgSatValue::Constant(!value),
                CfgSatValue::Literal(literal) => CfgSatValue::Literal(-literal),
            },
            CfgFormulaNode::All(children) | CfgFormulaNode::Any(children) => {
                let operands = children
                    .iter()
                    .map(|child| match values[*child] {
                        CfgSatValue::Constant(_) => {
                            unreachable!("cfg formula operators discard constant operands")
                        }
                        CfgSatValue::Literal(literal) => literal,
                    })
                    .collect::<Vec<_>>();
                variable_count += 1;
                let gate = cfg_sat_literal(variable_count - 1, true);
                match node {
                    CfgFormulaNode::All(_) => {
                        for operand in &operands {
                            clauses.push(vec![-gate, *operand]);
                        }
                        let mut clause = Vec::with_capacity(operands.len() + 1);
                        clause.push(gate);
                        clause.extend(operands.iter().map(|operand| -*operand));
                        clauses.push(clause);
                    }
                    CfgFormulaNode::Any(_) => {
                        let mut clause = Vec::with_capacity(operands.len() + 1);
                        clause.push(-gate);
                        clause.extend(operands.iter().copied());
                        clauses.push(clause);
                        for operand in &operands {
                            clauses.push(vec![gate, -*operand]);
                        }
                    }
                    _ => unreachable!("matched cfg formula operator"),
                }
                CfgSatValue::Literal(gate)
            }
        };
        values.push(value);
    }

    match values[root] {
        CfgSatValue::Constant(true) => return Some(vec![false; formula.undecidable.len()]),
        CfgSatValue::Constant(false) => return None,
        CfgSatValue::Literal(literal) => clauses.push(vec![literal]),
    }

    let mut assignment = vec![-1; variable_count];
    if !cfg_sat_search(&clauses, formula.undecidable.len(), &mut assignment) {
        return None;
    }
    Some(
        assignment
            .into_iter()
            .take(formula.undecidable.len())
            .map(|value| value == 1)
            .collect(),
    )
}

#[derive(Clone, Copy)]
enum CfgSatValue {
    Constant(bool),
    Literal(i32),
}

fn cfg_sat_literal(variable: usize, positive: bool) -> i32 {
    let literal = i32::try_from(variable + 1).expect("cfg SAT variable fits in a signed literal");
    if positive { literal } else { -literal }
}

fn cfg_sat_search(clauses: &[Vec<i32>], atom_count: usize, assignment: &mut [i8]) -> bool {
    if !cfg_sat_propagate(clauses, assignment) {
        return false;
    }
    let decision = (0..atom_count)
        .rev()
        .chain(atom_count..assignment.len())
        .find(|variable| assignment[*variable] == -1);
    let Some(variable) = decision else {
        return true;
    };

    for value in [0, 1] {
        let mut branch = assignment.to_vec();
        branch[variable] = value;
        if cfg_sat_search(clauses, atom_count, &mut branch) {
            assignment.copy_from_slice(&branch);
            return true;
        }
    }
    false
}

fn cfg_sat_propagate(clauses: &[Vec<i32>], assignment: &mut [i8]) -> bool {
    loop {
        let mut changed = false;
        for clause in clauses {
            let mut unresolved = None;
            let mut multiple_unresolved = false;
            let mut satisfied = false;
            for literal in clause {
                let variable = literal.unsigned_abs() as usize - 1;
                match assignment[variable] {
                    -1 => {
                        if unresolved.is_some() {
                            multiple_unresolved = true;
                            break;
                        }
                        unresolved = Some((*literal, variable));
                    }
                    value if (value == 1) == (*literal > 0) => {
                        satisfied = true;
                        break;
                    }
                    _ => {}
                }
            }
            if satisfied || multiple_unresolved {
                continue;
            }
            let Some((literal, variable)) = unresolved else {
                return false;
            };
            let value = if literal > 0 { 1 } else { 0 };
            match assignment[variable] {
                -1 => {
                    assignment[variable] = value;
                    changed = true;
                }
                current if current == value => {}
                _ => return false,
            }
        }
        if !changed {
            return true;
        }
    }
}

fn evaluate_with_assumptions(
    condition: &RustCfgCondition,
    contains: impl Fn(&str) -> bool,
    absent: impl Fn(&str) -> RustSelectedActivation,
    assumptions: &[(CfgLiteral, Option<bool>)],
) -> RustSelectedActivation {
    use RustSelectedActivation::{Active, Inactive, Unknown};
    let described = describes_target(&contains);
    let atom = |name: &str| {
        if let Some(assumption) = assumption_for(assumptions, &CfgLiteral::Atom(name.to_owned())) {
            assumed_activation(assumption)
        } else if contains(name) {
            Active
        } else if matches!(name, "test" | "debug_assertions")
            || (described && matches!(name, "unix" | "windows"))
        {
            Inactive
        } else {
            absent(name)
        }
    };
    let key_value = |key: &str, value: &str| {
        if let Some(assumption) = assumption_for(
            assumptions,
            &CfgLiteral::KeyValue {
                key: key.to_owned(),
                value: value.to_owned(),
            },
        ) {
            assumed_activation(assumption)
        } else if contains(&format!("{key} = {value:?}")) {
            Active
        } else if described && TARGET_CFG_KEYS.contains(&key) {
            Inactive
        } else {
            absent(&format!("{key} = {value:?}"))
        }
    };
    let instructions = match condition {
        RustCfgCondition::Always => return Active,
        RustCfgCondition::Unknown => return Unknown,
        RustCfgCondition::Atom(name) => return atom(name),
        RustCfgCondition::NotAtom(name) => {
            return match atom(name) {
                Active => Inactive,
                Inactive => Active,
                Unknown => Unknown,
            };
        }
        RustCfgCondition::Expression(instructions) => instructions.as_ref(),
    };
    let mut stack = Vec::new();
    for instruction in instructions {
        let value = match instruction {
            RustCfgInstruction::Atom(name) => atom(name),
            RustCfgInstruction::KeyValue { key, value } => key_value(key, value),
            RustCfgInstruction::Unknown => Unknown,
            RustCfgInstruction::Not => match stack.pop().expect("cfg negation has an operand") {
                Active => Inactive,
                Inactive => Active,
                Unknown => Unknown,
            },
            RustCfgInstruction::All(count) => {
                assert!(stack.len() >= *count, "cfg conjunction has its operands");
                let values = stack.split_off(stack.len() - *count);
                if values.contains(&Inactive) {
                    Inactive
                } else if values.contains(&Unknown) {
                    Unknown
                } else {
                    Active
                }
            }
            RustCfgInstruction::Any(count) => {
                assert!(stack.len() >= *count, "cfg disjunction has its operands");
                let values = stack.split_off(stack.len() - *count);
                if values.contains(&Active) {
                    Active
                } else if values.contains(&Unknown) {
                    Unknown
                } else {
                    Inactive
                }
            }
        };
        stack.push(value);
    }
    assert_eq!(stack.len(), 1, "cfg expression has exactly one result");
    stack[0]
}

fn assumed_activation(assumption: Option<bool>) -> RustSelectedActivation {
    match assumption {
        Some(true) => RustSelectedActivation::Active,
        Some(false) => RustSelectedActivation::Inactive,
        None => RustSelectedActivation::Unknown,
    }
}

fn assumption_for(
    assumptions: &[(CfgLiteral, Option<bool>)],
    literal: &CfgLiteral,
) -> Option<Option<bool>> {
    assumptions
        .iter()
        .find_map(|(candidate, value)| (candidate == literal).then_some(*value))
}

fn crate_cfg_literal_activation(
    atoms: &BTreeSet<String>,
    literal: &CfgLiteral,
) -> RustSelectedActivation {
    if let CfgLiteral::KeyValue { key, value } = literal
        && key == "feature"
        && !atoms.contains(INCOMPLETE_FEATURES_ATOM)
        && !atoms.contains(&format!("{key} = {value:?}"))
    {
        return RustSelectedActivation::Inactive;
    }
    cfg_literal_activation(atoms, literal, |name| absent_crate_atom(atoms, name))
}

fn detached_cfg_literal_activation(
    atoms: &BTreeSet<String>,
    literal: &CfgLiteral,
) -> RustSelectedActivation {
    cfg_literal_activation(atoms, literal, |_| RustSelectedActivation::Unknown)
}

fn cfg_literal_activation(
    atoms: &BTreeSet<String>,
    literal: &CfgLiteral,
    absent_atom: impl Fn(&str) -> RustSelectedActivation,
) -> RustSelectedActivation {
    use RustSelectedActivation::{Active, Inactive, Unknown};
    let described = describes_target(|name| atoms.contains(name));
    match literal {
        CfgLiteral::Atom(name) => {
            if atoms.contains(name) {
                Active
            } else if matches!(name.as_str(), "test" | "debug_assertions")
                || (described && matches!(name.as_str(), "unix" | "windows"))
            {
                Inactive
            } else {
                absent_atom(name)
            }
        }
        CfgLiteral::KeyValue { key, value } => {
            if atoms.contains(&format!("{key} = {value:?}")) {
                Active
            } else if described && TARGET_CFG_KEYS.contains(&key.as_str()) {
                Inactive
            } else {
                Unknown
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CfgLiteral, RustSelectedActivation, detached_site_cfg_activation};
    use brokk_bifrost_core::analyzer::rust_facts::{RustCfgCondition, RustCfgInstruction};
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::BTreeSet;

    fn expression(instructions: Vec<RustCfgInstruction>) -> RustCfgCondition {
        RustCfgCondition::Expression(instructions.into_boxed_slice())
    }

    fn key_value_any(key: &str, values: impl IntoIterator<Item = String>) -> RustCfgCondition {
        let mut instructions = Vec::new();
        let mut count = 0;
        for value in values {
            instructions.push(RustCfgInstruction::KeyValue {
                key: key.to_owned(),
                value,
            });
            count += 1;
        }
        instructions.push(RustCfgInstruction::Any(count));
        expression(instructions)
    }

    #[test]
    #[hardwon("#4481: a 42-version cfg predicate exceeded the assignment bound")]
    fn intel_simics_version_cfg_has_a_satisfying_witness() {
        let versions = (163..=194)
            .map(|patch| format!("6.0.{patch}"))
            .chain((0..=9).map(|minor| format!("7.{minor}.0")))
            .collect::<Vec<_>>();
        assert_eq!(versions.len(), 42);
        let condition = key_value_any("simics_version", versions);

        let (activation, conditional, assignment) =
            detached_site_cfg_activation(&BTreeSet::new(), &condition);

        assert_eq!(activation, RustSelectedActivation::Active);
        assert!(conditional);
        let assumptions = assignment.expect("wide any has a witness").assumptions;
        assert_eq!(assumptions.len(), 42);
        assert_eq!(
            assumptions[0],
            (
                CfgLiteral::KeyValue {
                    key: "simics_version".to_owned(),
                    value: "6.0.163".to_owned(),
                },
                Some(true),
            )
        );
        assert!(
            assumptions[1..]
                .iter()
                .all(|(_, value)| *value == Some(false))
        );

        let negated = expression(
            condition
                .instructions()
                .into_iter()
                .chain([RustCfgInstruction::Not])
                .collect(),
        );
        let (activation, conditional, assignment) =
            detached_site_cfg_activation(&BTreeSet::new(), &negated);
        assert_eq!(activation, RustSelectedActivation::Active);
        assert!(conditional);
        let assumptions = assignment
            .expect("negated wide any has a witness")
            .assumptions;
        assert!(assumptions.iter().all(|(_, value)| *value == Some(false)));
    }

    #[test]
    #[hardwon("#4481: wide cfg predicates exceeded the assignment bound")]
    fn wide_any_and_all_find_witnesses() {
        let atom_count = 128;
        let any = expression(
            (0..atom_count)
                .map(|index| RustCfgInstruction::Atom(format!("custom_{index}")))
                .chain([RustCfgInstruction::Any(atom_count)])
                .collect(),
        );
        let all = expression(
            (0..atom_count)
                .map(|index| RustCfgInstruction::Atom(format!("custom_{index}")))
                .chain([RustCfgInstruction::All(atom_count)])
                .collect(),
        );

        for (condition, expected_first, expected_last) in [(any, true, false), (all, true, true)] {
            let (activation, conditional, assignment) =
                detached_site_cfg_activation(&BTreeSet::new(), &condition);
            assert_eq!(activation, RustSelectedActivation::Active);
            assert!(conditional);
            let assumptions = assignment
                .expect("wide predicate has a witness")
                .assumptions;
            assert_eq!(assumptions.len(), atom_count);
            assert_eq!(assumptions[0].1, Some(expected_first));
            assert_eq!(assumptions[atom_count - 1].1, Some(expected_last));
            if expected_last {
                assert!(assumptions.iter().all(|(_, value)| *value == Some(true)));
            } else {
                assert!(
                    assumptions[1..]
                        .iter()
                        .all(|(_, value)| *value == Some(false))
                );
            }
        }
    }

    #[test]
    #[hardwon("#4481: selected cfg values must constrain unknown site literals")]
    fn known_cfg_values_are_simplified_before_solving() {
        let known_true = expression(vec![
            RustCfgInstruction::Atom("test".to_owned()),
            RustCfgInstruction::Atom("custom".to_owned()),
            RustCfgInstruction::Any(2),
        ]);
        let known_false = expression(vec![
            RustCfgInstruction::Atom("test".to_owned()),
            RustCfgInstruction::Atom("custom".to_owned()),
            RustCfgInstruction::All(2),
        ]);

        let atoms = BTreeSet::from(["test".to_owned()]);
        let (activation, conditional, assignment) =
            detached_site_cfg_activation(&atoms, &known_true);
        assert_eq!(activation, RustSelectedActivation::Active);
        assert!(conditional);
        assert_eq!(
            assignment
                .expect("custom atom remains a site assumption")
                .assumptions,
            vec![(CfgLiteral::Atom("custom".to_owned()), Some(false))]
        );

        let (activation, conditional, assignment) =
            detached_site_cfg_activation(&BTreeSet::new(), &known_false);
        assert_eq!(activation, RustSelectedActivation::Inactive);
        assert!(!conditional);
        assert!(assignment.is_none());
    }

    #[test]
    #[hardwon("#4481: repeated cfg atoms need one shared SAT assignment")]
    fn repeated_atoms_are_consistent_across_branches() {
        let contradiction = expression(vec![
            RustCfgInstruction::Atom("custom".to_owned()),
            RustCfgInstruction::Atom("custom".to_owned()),
            RustCfgInstruction::Not,
            RustCfgInstruction::All(2),
        ]);
        let tautology = expression(vec![
            RustCfgInstruction::Atom("custom".to_owned()),
            RustCfgInstruction::Atom("custom".to_owned()),
            RustCfgInstruction::Not,
            RustCfgInstruction::Any(2),
        ]);
        let related_branches = expression(vec![
            RustCfgInstruction::Atom("shared".to_owned()),
            RustCfgInstruction::Atom("left".to_owned()),
            RustCfgInstruction::All(2),
            RustCfgInstruction::Atom("shared".to_owned()),
            RustCfgInstruction::Atom("right".to_owned()),
            RustCfgInstruction::Not,
            RustCfgInstruction::All(2),
            RustCfgInstruction::Any(2),
        ]);

        let (activation, conditional, assignment) =
            detached_site_cfg_activation(&BTreeSet::new(), &contradiction);
        assert_eq!(activation, RustSelectedActivation::Inactive);
        assert!(!conditional);
        assert!(assignment.is_none());

        let (activation, conditional, assignment) =
            detached_site_cfg_activation(&BTreeSet::new(), &tautology);
        assert_eq!(activation, RustSelectedActivation::Active);
        assert!(conditional);
        assert_eq!(
            assignment.expect("tautology has a witness").assumptions,
            vec![(CfgLiteral::Atom("custom".to_owned()), Some(false))]
        );

        let (activation, conditional, assignment) =
            detached_site_cfg_activation(&BTreeSet::new(), &related_branches);
        assert_eq!(activation, RustSelectedActivation::Active);
        assert!(conditional);
        let assumptions = assignment
            .expect("one related branch is satisfiable")
            .assumptions;
        assert_eq!(assumptions.len(), 3);
        assert_eq!(
            assumptions[0],
            (CfgLiteral::Atom("shared".to_owned()), Some(true))
        );
    }
}

#[cfg(test)]
mod site_worlds_properties {
    use super::{
        RustCfgCondition, RustCfgInstruction, RustSelectedActivation, crate_activation,
        crate_activation_under_site_cfg, crate_site_cfg_activation, detached_activation,
        detached_activation_under_site_cfg, detached_site_cfg_activation,
    };
    use brokk_bifrost_test_macros::hardwon;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    // This bounded test AST is independent of the production postfix evaluator
    // and SAT representation. Recursion is bounded to three generated levels
    // plus the contradiction/tautology wrapper below.
    #[derive(Clone, Debug)]
    enum Predicate {
        Literal(usize),
        Not(Box<Self>),
        All(Vec<Self>),
        Any(Vec<Self>),
    }

    impl Predicate {
        fn eval(&self, values: &[i8]) -> i8 {
            match self {
                Self::Literal(index) => values[*index],
                Self::Not(child) => -child.eval(values),
                Self::All(children) => children
                    .iter()
                    .map(|child| child.eval(values))
                    .min()
                    .unwrap_or(1),
                Self::Any(children) => children
                    .iter()
                    .map(|child| child.eval(values))
                    .max()
                    .unwrap_or(-1),
            }
        }

        fn emit(&self, literals: &[RustCfgInstruction], output: &mut Vec<RustCfgInstruction>) {
            match self {
                Self::Literal(index) => output.push(literals[*index].clone()),
                Self::Not(child) => {
                    child.emit(literals, output);
                    output.push(RustCfgInstruction::Not);
                }
                Self::All(children) | Self::Any(children) => {
                    for child in children {
                        child.emit(literals, output);
                    }
                    output.push(match self {
                        Self::All(_) => RustCfgInstruction::All(children.len()),
                        Self::Any(_) => RustCfgInstruction::Any(children.len()),
                        _ => unreachable!(),
                    });
                }
            }
        }

        fn condition(&self, literals: &[RustCfgInstruction]) -> RustCfgCondition {
            let mut output = Vec::new();
            self.emit(literals, &mut output);
            RustCfgCondition::Expression(output.into_boxed_slice())
        }

        fn used(&self, used: &mut [bool]) {
            match self {
                Self::Literal(index) => used[*index] = true,
                Self::Not(child) => child.used(used),
                Self::All(children) | Self::Any(children) => {
                    for child in children {
                        child.used(used);
                    }
                }
            }
        }
    }

    fn predicate(count: usize) -> BoxedStrategy<Predicate> {
        (0..count)
            .prop_map(Predicate::Literal)
            .prop_recursive(3, 24, 3, |inner| {
                prop_oneof![
                    inner
                        .clone()
                        .prop_map(|child| Predicate::Not(Box::new(child))),
                    prop::collection::vec(inner.clone(), 0..4).prop_map(Predicate::All),
                    prop::collection::vec(inner, 0..4).prop_map(Predicate::Any),
                ]
            })
            .boxed()
    }

    fn activation(value: i8) -> RustSelectedActivation {
        match value {
            -1 => RustSelectedActivation::Inactive,
            0 => RustSelectedActivation::Unknown,
            1 => RustSelectedActivation::Active,
            _ => unreachable!(),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        #[hardwon("a48b9658c627: quicksilver round 3 on brokk-bifrost-rust: absent key-value features stayed unknown in complete cfg inventories")]
        fn site_worlds_match_exhaustive_assignments(
            (selected, site, candidate) in prop::collection::btree_set(0usize..10, 2..5)
                .prop_flat_map(|selected| {
                    let count = selected.len();
                    (Just(selected), predicate(count), predicate(count))
                }),
            enabled in 0u16..1024,
            described in any::<bool>(),
        ) {
            // Each pool entry has an independently specified spelling, source
            // instruction, and absent value for an ordinary three-valued read.
            let pool = [
                ("custom_a", RustCfgInstruction::Atom("custom_a".into()), 0),
                ("custom_b", RustCfgInstruction::Atom("custom_b".into()), 0),
                ("feature = \"fast\"", RustCfgInstruction::KeyValue { key: "feature".into(), value: "fast".into() }, 0),
                ("feature = \"slow\"", RustCfgInstruction::KeyValue { key: "feature".into(), value: "slow".into() }, 0),
                ("target_os = \"linux\"", RustCfgInstruction::KeyValue { key: "target_os".into(), value: "linux".into() }, if described { -1 } else { 0 }),
                ("target_endian = \"big\"", RustCfgInstruction::KeyValue { key: "target_endian".into(), value: "big".into() }, if described { -1 } else { 0 }),
                ("test", RustCfgInstruction::Atom("test".into()), -1),
                ("debug_assertions", RustCfgInstruction::Atom("debug_assertions".into()), -1),
                ("unix", RustCfgInstruction::Atom("unix".into()), if described { -1 } else { 0 }),
                ("windows", RustCfgInstruction::Atom("windows".into()), if described { -1 } else { 0 }),
            ];
            // Endianness is inserted only here, so an undescribed inventory
            // cannot accidentally become described through the enabled mask.
            let atoms: BTreeSet<String> = pool.iter().enumerate()
                .filter(|(index, _)| *index != 5 && enabled & (1 << index) != 0)
                .map(|(_, (name, _, _))| (*name).to_owned())
                .chain(described.then(|| "target_endian = \"little\"".to_owned()))
                .collect();
            let selected: Vec<_> = selected.into_iter().collect();
            let literals: Vec<_> = selected.iter().map(|index| pool[*index].1.clone()).collect();
            let ordinary: Vec<_> = selected.iter().map(|index| {
                if atoms.contains(pool[*index].0) { 1 } else { pool[*index].2 }
            }).collect();
            let negated = Predicate::Not(Box::new(site.clone()));
            // Every generated case also exercises repeated literals and both
            // correlated extremes, rather than relying on random discovery.
            let sites = [site.clone(), Predicate::All(vec![site.clone(), negated.clone()]),
                Predicate::Any(vec![site, negated]), Predicate::All(vec![]), Predicate::Any(vec![])];
            for complete in [false, true] {
                let read = if complete { crate_activation } else { detached_activation };
                let site_read = if complete { crate_site_cfg_activation } else { detached_site_cfg_activation };
                let under = if complete { crate_activation_under_site_cfg } else { detached_activation_under_site_cfg };
                let ordinary: Vec<_> = ordinary.iter().enumerate().map(|(local, value)| {
                    if complete && matches!(selected[local], 2 | 3) && *value == 0 { -1 } else { *value }
                }).collect();
                prop_assert_eq!(read(&atoms, &candidate.condition(&literals)), activation(candidate.eval(&ordinary)));
                prop_assert_eq!(under(&atoms, &candidate.condition(&literals), None), activation(candidate.eval(&ordinary)));
                for site in &sites {
                    let condition = site.condition(&literals);
                    let mut used = vec![false; selected.len()];
                    site.used(&mut used);
                    let fixed = ordinary.clone();
                    let unknown: Vec<_> = (0..selected.len()).filter(|index| used[*index] && fixed[*index] == 0).collect();
                    let worlds: Vec<_> = (0..(1 << unknown.len())).map(|mask| {
                        let mut world = fixed.clone();
                        for (bit, index) in unknown.iter().enumerate() {
                            world[*index] = if mask & (1 << bit) != 0 { 1 } else { -1 };
                        }
                        world
                    }).filter(|world| site.eval(world) == 1).collect();
                    let expected = if unknown.is_empty() {
                        activation(site.eval(&ordinary))
                    } else if worlds.is_empty() {
                        RustSelectedActivation::Inactive
                    } else {
                        RustSelectedActivation::Active
                    };
                    let (actual, conditional, assignment) = site_read(&atoms, &condition);
                    prop_assert_eq!(actual, expected, "site={:?}, complete={}, atoms={:?}", site, complete, atoms);
                    prop_assert_eq!(conditional, !unknown.is_empty() && !worlds.is_empty());
                    prop_assert_eq!(assignment.is_some(), conditional);
                    if let Some(assignment) = assignment {
                        prop_assert_eq!(under(&atoms, &condition, Some(&assignment)), RustSelectedActivation::Active);
                        prop_assert_eq!(under(&atoms, &Predicate::Not(Box::new(site.clone())).condition(&literals), Some(&assignment)), RustSelectedActivation::Inactive);
                        // Recover the chosen truth values using the public
                        // candidate API, never the solver's internal formula.
                        let mut witnessed = ordinary.clone();
                        for index in &unknown {
                            let value = under(&atoms, &Predicate::Literal(*index).condition(&literals), Some(&assignment));
                            prop_assert_ne!(value, RustSelectedActivation::Unknown);
                            witnessed[*index] = if value == RustSelectedActivation::Active { 1 } else { -1 };
                        }
                        prop_assert!(worlds.iter().any(|world| unknown.iter().all(|index| world[*index] == witnessed[*index])));
                        prop_assert_eq!(under(&atoms, &candidate.condition(&literals), Some(&assignment)), activation(candidate.eval(&witnessed)));
                        prop_assert_eq!(under(&atoms, &RustCfgCondition::Atom("unrelated".into()), Some(&assignment)), RustSelectedActivation::Unknown);
                        // Contradiction with the selected world must be false.
                        for index in &unknown {
                            let literal = Predicate::Literal(*index);
                            let opposite = if witnessed[*index] == 1 { Predicate::Not(Box::new(literal)) } else { literal };
                            prop_assert_eq!(under(&atoms, &opposite.condition(&literals), Some(&assignment)), RustSelectedActivation::Inactive);
                        }
                    }
                }
            }
        }
    }
}
