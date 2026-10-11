use std::fmt::Display;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, de};

pub(crate) fn deserialize_from_string<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: Display,
{
    String::deserialize(deserializer)?
        .parse()
        .map_err(de::Error::custom)
}
