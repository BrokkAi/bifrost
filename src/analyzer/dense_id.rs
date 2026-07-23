//! Shared fixed-width dense identifier machinery.

use std::fmt;

/// A failed conversion from a collection index to a fixed-width dense ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenseIdOverflow {
    id_type: &'static str,
    index: usize,
}

impl DenseIdOverflow {
    pub(crate) const fn new(id_type: &'static str, index: usize) -> Self {
        Self { id_type, index }
    }

    pub const fn id_type(self) -> &'static str {
        self.id_type
    }

    pub const fn index(self) -> usize {
        self.index
    }
}

impl fmt::Display for DenseIdOverflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} index {} does not fit in a u32",
            self.id_type, self.index
        )
    }
}

impl std::error::Error for DenseIdOverflow {}

macro_rules! define_dense_id {
    (
        $(#[$attribute:meta])*
        $type_visibility:vis struct $name:ident {
            new: $new_visibility:vis,
            get: $get_visibility:vis,
            index: $index_visibility:vis,
            try_from_index: $try_visibility:vis $(,)?
        }
    ) => {
        $(#[$attribute])*
        $type_visibility struct $name(u32);

        impl $name {
            $new_visibility const fn new(raw: u32) -> Self {
                Self(raw)
            }

            $get_visibility const fn get(self) -> u32 {
                self.0
            }

            $index_visibility const fn index(self) -> usize {
                self.0 as usize
            }

            $try_visibility fn try_from_index(
                index: usize,
            ) -> Result<Self, $crate::analyzer::dense_id::DenseIdOverflow> {
                <u32 as ::std::convert::TryFrom<usize>>::try_from(index)
                    .map(Self)
                    .map_err(|_| {
                        $crate::analyzer::dense_id::DenseIdOverflow::new(
                            stringify!($name),
                            index,
                        )
                    })
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

pub(crate) use define_dense_id;
