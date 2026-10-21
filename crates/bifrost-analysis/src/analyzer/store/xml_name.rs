#[doc(hidden)]
pub fn local_xml_name(name: &[u8]) -> Option<String> {
    let name = std::str::from_utf8(name).ok()?;
    Some(
        name.rsplit_once(':')
            .map(|(_, local)| local)
            .unwrap_or(name)
            .to_owned(),
    )
}
