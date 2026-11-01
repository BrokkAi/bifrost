use super::*;

#[test]
fn string_charges_spare_capacity_at_byte_boundary() {
    let mut value = String::with_capacity(128);
    value.push_str("evidence");
    let exact = size_of::<String>() + value.capacity();
    assert!(value.capacity() > value.len());
    assert_eq!(value.retained_size(), exact);
    assert!(value.retained_size() <= exact);
    assert!(value.retained_size() > exact - 1);
}

#[test]
fn boxed_text_charges_inline_pointer_at_byte_boundary() {
    let value: Box<str> = "evidence".into();
    let exact = size_of::<Box<str>>() + value.len();
    assert_eq!(value.retained_size(), exact);
    assert!(value.retained_size() <= exact);
    assert!(value.retained_size() > exact - 1);
}

#[test]
fn json_object_key_charges_reserved_capacity_at_byte_boundary() {
    let mut key = String::with_capacity(128);
    key.push_str("signal");
    let capacity = key.capacity();
    let mut object = serde_json::Map::new();
    object.insert(key, serde_json::Value::Null);
    let value = serde_json::Value::Object(object);
    let exact = size_of::<serde_json::Value>()
        + size_of::<String>()
        + size_of::<serde_json::Value>()
        + capacity;
    assert_eq!(value.retained_size(), exact);
    assert!(value.retained_size() <= exact);
    assert!(value.retained_size() > exact - 1);
}

#[test]
fn workspace_path_charges_inline_storage_at_byte_boundary() {
    let path = WorkspaceRelativePath::new("src/very/long/nested/file.rs").unwrap();
    let exact = size_of::<WorkspaceRelativePath>() + path.as_str().len();
    assert_eq!(path.retained_size(), exact);
    assert!(path.retained_size() <= exact);
    assert!(path.retained_size() > exact - 1);
}
