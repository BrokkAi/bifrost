use super::*;
use crate::analyzer::Language;
use crate::inline_project::InlineTestProject;
use brokk_bifrost_core::analyzer::rust_facts::RustDeclarationKind;

#[test]
fn enum_variant_classification_uses_the_field_property_without_owner_rows() {
    let source = r#"
macro_rules! cfg_net {
    ($($item:item)*) => { $($item)* };
}

cfg_net! {
    pub struct TcpListener {
        io: usize,
    }
}

enum Mode { Ready }

fn bind_fields(listener: TcpListener, mode: Mode) {
    let TcpListener { io } = listener;
    let Mode::Ready = mode;
    let _ = io;
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let rust = RustAnalyzer::new(project.project_dyn());
    let file = project.file("src/lib.rs");
    let (generation, oid) = rust
        .selected_rust_source(&file)
        .expect("fixture source is in the canonical Rust snapshot");
    let mut properties = (*rust
        .declaration_source_properties(&file, &|| true)
        .expect("canonical declaration properties"))
    .clone();
    let find = |name: &str| {
        properties
            .keys()
            .find(|unit| unit.kind() == CodeUnitType::Field && unit.identifier() == name)
            .cloned()
            .unwrap_or_else(|| panic!("missing Field {name} in {properties:?}"))
    };
    let io = find("io");
    let ready = find("Ready");
    let io_owner = rust
        .structural_parent_of(&io)
        .expect("macro field has its structural owner");
    let ready_owner = rust
        .structural_parent_of(&ready)
        .expect("enum variant has its structural owner");
    assert_eq!(properties[&io][0].kind, RustDeclarationKind::Field);
    assert_eq!(properties[&ready][0].kind, RustDeclarationKind::EnumVariant);

    // Source properties classify their own unit. Owner rows are not part of
    // this query's input and may be absent from the canonical unit map.
    properties.remove(&io_owner);
    properties.remove(&ready_owner);
    rust.declaration_source_properties
        .insert((generation, oid, file), Arc::new(properties));

    assert!(!rust_declaration_is_enum_variant(&rust, &io).expect("field property is available"));
    assert!(
        rust_declaration_is_enum_variant(&rust, &ready)
            .expect("enum variant property is available")
    );
}

#[test]
fn enum_variant_classification_catches_up_missing_declaration_facts_for_all_field_shapes() {
    let source = r#"
macro_rules! cfg_net {
    ($($item:item)*) => { $($item)* };
}

cfg_net! {
    pub struct TcpListener {
        io: usize,
    }
}

#[transition::versioned(versions("0"))]
pub struct Endorsement {
    slot: usize,
}

pub struct Win32Error(u32);

#[cfg(any())]
impl Win32Error {
    const SHARING_VIOLATION: Win32Error = Win32Error(32);
}

mod setup {
    fn target() {}
}

macro_rules! setup_fn {
    ($func:path) => { SetupFn::new($func) };
}

pub struct SetupFn {
    func: fn(),
}

impl SetupFn {
    fn new(func: fn()) -> Self {
        Self { func }
    }
}

#[divan::bench(args = [setup_fn!(setup::target)])]
fn vortex_bench() {}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let rust = RustAnalyzer::new(project.project_dyn());
    let file = project.file("src/lib.rs");
    let _ = rust.get_analyzed_files();
    let declarations = rust.declarations(&file);
    let field = |short_name: &str| {
        declarations
            .iter()
            .find(|unit| unit.kind() == CodeUnitType::Field && unit.short_name() == short_name)
            .cloned()
            .unwrap_or_else(|| panic!("missing field {short_name:?}: {declarations:?}"))
    };
    let fields = [
        (field("TcpListener.io"), false),
        (field("Endorsement.slot"), false),
        (field("Win32Error.SHARING_VIOLATION"), false),
        (field("SetupFn.func"), false),
    ];

    rust.analyzer_store().delete_rust_facts_for_test("rust");
    assert_eq!(
        rust.rust_files_without_facts_among(std::slice::from_ref(&file))
            .expect("missing fact probe"),
        vec![file.clone()]
    );

    for (declaration, expected) in fields {
        assert_eq!(
            rust_declaration_is_enum_variant(&rust, &declaration)
                .expect("declaration facts are caught up before classification"),
            expected,
            "{declaration:?}"
        );
    }
    assert!(
        rust.rust_files_without_facts_among(std::slice::from_ref(&file))
            .expect("published fact probe")
            .is_empty()
    );
}
