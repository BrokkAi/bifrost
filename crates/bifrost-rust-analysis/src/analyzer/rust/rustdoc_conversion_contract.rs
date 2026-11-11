// Shared by the offline converter and the producer's field-consumption tripwire.
// (field name, producer read pattern, first legacy format, last legacy format)
pub const UNCERTIFIED_FIELD_READS: &[(&str, &str, u64, u64)] = &[
    ("Item::stability", ".stability", 54, 57),
    ("Item::const_stability", ".const_stability", 54, 57),
    ("Function::default_unstable", ".default_unstable", 54, 57),
    ("AssocConst::default_unstable", ".default_unstable", 54, 57),
    ("AssocType::default_unstable", ".default_unstable", 54, 57),
    ("ExternalCrate::path", "external.path", 54, 56),
    ("Attribute::MacroExport", ".attrs", 54, 54),
];
