use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{
    fmt,
    path::{Component, Path},
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StableDigest(Box<str>);

impl StableDigest {
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("digest must be 64 lowercase hexadecimal characters".into());
        }
        Ok(Self(value.into_boxed_str()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for StableDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl Serialize for StableDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for StableDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkspaceGeneration(StableDigest);
impl WorkspaceGeneration {
    pub(crate) fn new(digest: StableDigest) -> Self {
        Self(digest)
    }
    pub fn digest(&self) -> &StableDigest {
        &self.0
    }
}
impl fmt::Display for WorkspaceGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NormalizedRelativePath(Box<str>);
impl NormalizedRelativePath {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let raw = path.to_str().ok_or("path must be UTF-8")?;
        if path.as_os_str().is_empty() || path.is_absolute() {
            return Err("path must be nonempty and relative".into());
        }
        if raw.contains('\\')
            || raw.contains('\0')
            || raw
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err("path contains a noncanonical segment".into());
        }
        let mut parts = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(part) => {
                    let part = part.to_str().ok_or("path must be UTF-8")?;
                    if part.is_empty() || part.contains(['\\', '\0']) {
                        return Err("path contains a noncanonical segment".into());
                    }
                    parts.push(part);
                }
                _ => {
                    return Err(
                        "path must not contain root, prefix, dot, or parent segments".into(),
                    );
                }
            }
        }
        Ok(Self(parts.join("/").into_boxed_str()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl Serialize for NormalizedRelativePath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for NormalizedRelativePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(Path::new(&value)).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub path: NormalizedRelativePath,
    pub start_utf8_byte: u64,
    pub end_utf8_byte: u64,
}
impl SourceSpan {
    pub fn validate(&self) -> Result<(), String> {
        if self.start_utf8_byte > self.end_utf8_byte {
            Err("source span start exceeds end".into())
        } else {
            Ok(())
        }
    }
}
