use std::fmt::Display;
use std::str::FromStr;

pub(super) fn validate_shard<T>(index: T, count: T) -> Result<(), String>
where
    T: Copy + Default + Display + PartialOrd,
{
    let zero = T::default();
    if count == zero {
        return Err("--shard count must be at least 1".to_string());
    }
    if index == zero || index > count {
        return Err(format!("--shard index {index} is out of range 1..={count}"));
    }
    Ok(())
}

pub(super) fn parse_shard<T: FromStr>(value: &str) -> Result<(T, T), String> {
    let (index, count) = value
        .split_once('/')
        .ok_or_else(|| format!("--shard expects K/N, got `{value}`"))?;
    let index = index
        .parse::<T>()
        .map_err(|_| format!("--shard index `{index}` is not a positive integer"))?;
    let count = count
        .parse::<T>()
        .map_err(|_| format!("--shard count `{count}` is not a positive integer"))?;
    Ok((index, count))
}
