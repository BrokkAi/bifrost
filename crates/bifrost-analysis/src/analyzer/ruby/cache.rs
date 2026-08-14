use super::*;
use std::mem::size_of;
use std::sync::Arc;

pub(super) fn weight_code_unit_vec(_key: &CodeUnit, value: &Arc<Vec<CodeUnit>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.fq_name().len() + size_of::<CodeUnit>())
        .sum::<usize>()
        + size_of::<Vec<CodeUnit>>();
    size.min(u32::MAX as usize) as u32
}
