//! Shared validation and newtype generation for analyzer identifiers.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierError {
    Empty,
    TooLong { max_bytes: usize },
    NonAscii,
    InvalidStart,
    InvalidEnd,
    InvalidCharacter { index: usize },
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("identifier must not be empty"),
            Self::TooLong { max_bytes } => {
                write!(formatter, "identifier must be at most {max_bytes} bytes")
            }
            Self::NonAscii => formatter.write_str("identifier must contain only ASCII characters"),
            Self::InvalidStart => {
                formatter.write_str("identifier must begin with a lowercase ASCII alphanumeric")
            }
            Self::InvalidEnd => {
                formatter.write_str("identifier must end with a lowercase ASCII alphanumeric")
            }
            Self::InvalidCharacter { index } => {
                write!(
                    formatter,
                    "identifier has an invalid character at byte {index}"
                )
            }
        }
    }
}

impl std::error::Error for IdentifierError {}

pub fn validate_identifier(
    value: &str,
    max_bytes: usize,
    allow_dot: bool,
) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty);
    }
    if value.len() > max_bytes {
        return Err(IdentifierError::TooLong { max_bytes });
    }
    if !value.is_ascii() {
        return Err(IdentifierError::NonAscii);
    }
    let bytes = value.as_bytes();
    if !is_lower_alphanumeric(bytes[0]) {
        return Err(IdentifierError::InvalidStart);
    }
    if !is_lower_alphanumeric(bytes[bytes.len() - 1]) {
        return Err(IdentifierError::InvalidEnd);
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        if !(is_lower_alphanumeric(byte)
            || byte == b'-'
            || byte == b'_'
            || allow_dot && byte == b'.')
        {
            return Err(IdentifierError::InvalidCharacter { index });
        }
    }
    Ok(())
}

const fn is_lower_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

/// Generates a validated identifier newtype. Exported because
/// brokk-bifrost-policy defines its own policy/taint/typestate identifiers with
/// exactly these rules.
#[macro_export]
macro_rules! define_identifier {
    (
        $(#[$attribute:meta])*
        $visibility:vis struct $name:ident {
            max_bytes: $max_bytes:expr,
            allow_dot: $allow_dot:expr,
            error: $error:ty $(,)?
        }
    ) => {
        $(#[$attribute])*
        $visibility struct $name(Box<str>);

        impl $name {
            pub fn new(value: impl AsRef<str>) -> Result<Self, $error> {
                let value = value.as_ref();
                $crate::analyzer::identifier::validate_identifier(
                    value,
                    $max_bytes,
                    $allow_dot,
                )?;
                Ok(Self(value.into()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(
                &self,
                formatter: &mut ::std::fmt::Formatter<'_>,
            ) -> ::std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

// `#[macro_export]` puts the macro at the crate root; this re-export keeps the
// descriptive `analyzer::identifier::define_identifier` path working.
pub use crate::define_identifier;
