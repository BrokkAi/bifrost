//! Selected host cfg inventory. Source producers never consult this module.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use brokk_bifrost_core::analyzer::rust_facts::{RustCfgCondition, RustCfgInstruction};

use crate::selected_context::{RustCallerTargetProfile, RustSelectedActivation};

struct HostCfg {
    atoms: BTreeSet<String>,
    values: [(&'static str, String); 5],
}

fn host_cfg() -> &'static HostCfg {
    static HOST: OnceLock<HostCfg> = OnceLock::new();
    HOST.get_or_init(|| {
        let mut atoms = BTreeSet::from(["test".to_string(), "debug_assertions".to_string()]);
        if cfg!(unix) {
            atoms.insert("unix".to_string());
        }
        if cfg!(windows) {
            atoms.insert("windows".to_string());
        }
        HostCfg {
            atoms,
            values: [
                ("target_os", std::env::consts::OS.to_string()),
                ("target_arch", std::env::consts::ARCH.to_string()),
                ("target_family", std::env::consts::FAMILY.to_string()),
                ("target_pointer_width", usize::BITS.to_string()),
                (
                    "target_endian",
                    if cfg!(target_endian = "little") {
                        "little"
                    } else {
                        "big"
                    }
                    .to_string(),
                ),
            ],
        }
    })
}

pub fn default_cfg_atoms() -> BTreeSet<String> {
    let host = host_cfg();
    let mut atoms = host.atoms.clone();
    atoms.extend(
        host.values
            .iter()
            .map(|(key, value)| format!("{key} = {value:?}")),
    );
    atoms
}

pub(crate) fn activation(
    profile: &RustCallerTargetProfile,
    condition: &RustCfgCondition,
) -> RustSelectedActivation {
    use RustSelectedActivation::{Active, Inactive, Unknown};
    let host = host_cfg();
    let atom = |name: &str| {
        if host.atoms.contains(name)
            || profile.cfg_atoms.contains(name)
            || profile
                .features
                .iter()
                .any(|feature| name == format!("feature = {feature:?}"))
        {
            Active
        } else if matches!(name, "unix" | "windows" | "test" | "debug_assertions") {
            Inactive
        } else {
            Unknown
        }
    };
    evaluate(condition, atom)
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
    use RustSelectedActivation::{Active, Inactive, Unknown};
    evaluate(condition, |name| {
        if atoms.contains(name) {
            Active
        } else if matches!(name, "unix" | "windows" | "test" | "debug_assertions") {
            Inactive
        } else {
            Unknown
        }
    })
}

/// One complete Cargo feature set: absent features are false; custom atoms
/// without an inventory remain unknown. No crate state is retained.
pub fn crate_activation(
    atoms: &BTreeSet<String>,
    condition: &RustCfgCondition,
) -> RustSelectedActivation {
    use RustSelectedActivation::{Active, Inactive, Unknown};
    evaluate(condition, |name| {
        if atoms.contains(name) {
            Active
        } else if name.starts_with("feature = ")
            || matches!(name, "unix" | "windows" | "test" | "debug_assertions")
        {
            Inactive
        } else {
            Unknown
        }
    })
}

fn evaluate(
    condition: &RustCfgCondition,
    atom: impl Fn(&str) -> RustSelectedActivation,
) -> RustSelectedActivation {
    use RustSelectedActivation::{Active, Inactive, Unknown};
    let host = host_cfg();
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
    let mut unknown = false;
    for instruction in instructions {
        let value = match instruction {
            RustCfgInstruction::Atom(name) => atom(name),
            RustCfgInstruction::KeyValue { key, value } => {
                match host.values.iter().find(|(name, _)| *name == key.as_str()) {
                    Some((_, selected)) if selected == value => Active,
                    Some(_) => Inactive,
                    None => Unknown,
                }
            }
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
                } else {
                    Active
                }
            }
            RustCfgInstruction::Any(count) => {
                assert!(stack.len() >= *count, "cfg disjunction has its operands");
                let values = stack.split_off(stack.len() - *count);
                if values.contains(&Active) {
                    Active
                } else {
                    Inactive
                }
            }
        };
        unknown |= value == Unknown;
        stack.push(value);
    }
    assert_eq!(stack.len(), 1, "cfg expression has exactly one result");
    if unknown { Unknown } else { stack[0] }
}
