//! Deserialization helpers for RouterOS quirks.
//!
//! RouterOS returns **all** values as JSON strings — booleans are `"true"` / `"false"`,
//! numbers are `"1234"`, etc. These helpers convert them to native Rust types.

use serde::Deserialize;

/// Deserialize `"true"` / `"false"` strings into `bool`.
pub fn ros_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(s == "true")
}

/// Deserialize optional `"true"` / `"false"` strings into `Option<bool>`.
/// Missing fields deserialize as `None`.
pub fn ros_bool_opt<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    Ok(s.map(|s| s == "true"))
}

/// Deserialize a string-encoded `u64`.
pub fn ros_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse::<u64>().map_err(serde::de::Error::custom)
}

/// Deserialize an optional string-encoded `u64`.
/// Non-numeric values (e.g. `"auto"`) return `None`.
pub fn ros_u64_opt<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) if !s.is_empty() => Ok(s.parse::<u64>().ok()),
        _ => Ok(None),
    }
}

/// Deserialize a string-encoded `i64`.
#[allow(dead_code)]
pub fn ros_i64<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse::<i64>().map_err(serde::de::Error::custom)
}

/// Deserialize a string-encoded `u32`.
pub fn ros_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse::<u32>().map_err(serde::de::Error::custom)
}

/// Deserialize an optional string-encoded `u32`.
/// Non-numeric values (e.g. `"auto"`) return `None`.
pub fn ros_u32_opt<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) if !s.is_empty() => Ok(s.parse::<u32>().ok()),
        _ => Ok(None),
    }
}
