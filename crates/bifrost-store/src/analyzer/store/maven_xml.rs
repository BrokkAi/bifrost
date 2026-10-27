use crate::analyzer::store::xml_name::local_xml_name;

use crate::hash::HashMap;
use crate::hash::HashSet;

use quick_xml::Reader;
use quick_xml::events::Event;

/// The per-file cap on build metadata reads, published through
/// `DependencyResolver::bounds` so a host can see what JVM discovery spends.
pub const MAX_BUILD_METADATA_BYTES: usize = 2 * 1024 * 1024;

pub const MAX_MAVEN_XML_DEPTH: usize = 128;

pub const MAX_MAVEN_XML_NODES: usize = 16 * 1024;

pub const MAX_MAVEN_PROPERTY_EXPANSION_WORK: usize = 4 * 1024;

pub const MAX_MAVEN_EXPANDED_VALUE_BYTES: usize = 64 * 1024;

pub fn maven_project_properties(project_node: &XmlNode) -> HashMap<String, String> {
    let mut properties = HashMap::default();
    if let Some(property_node) = project_node.child("properties") {
        for child in &property_node.children {
            let value = child.text.trim();
            if !child.name.is_empty() && !value.is_empty() {
                properties.insert(child.name.clone(), value.to_string());
            }
        }
    }
    let parent = project_node.child("parent");
    let project_group = project_node
        .child_text("groupId")
        .or_else(|| parent.and_then(|node| node.child_text("groupId")));
    let project_artifact = project_node.child_text("artifactId");
    let project_version = project_node
        .child_text("version")
        .or_else(|| parent.and_then(|node| node.child_text("version")));
    for (key, value) in [
        ("project.groupId", project_group),
        ("pom.groupId", project_group),
        ("project.artifactId", project_artifact),
        ("pom.artifactId", project_artifact),
        ("project.version", project_version),
        ("pom.version", project_version),
    ] {
        if let Some(value) = value {
            properties.insert(key.to_string(), value.to_string());
        }
    }
    properties
}

pub fn expand_maven_value(value: &str, properties: &HashMap<String, String>) -> Option<String> {
    enum Work {
        Value(String),
        Text(String),
        Property(String),
        LeaveProperty(String),
    }

    let mut active = HashSet::default();
    let mut work = vec![Work::Value(value.trim().to_string())];
    let mut result = String::new();
    let mut steps = 0usize;
    while let Some(next) = work.pop() {
        steps = steps.checked_add(1)?;
        if steps > MAX_MAVEN_PROPERTY_EXPANSION_WORK {
            return None;
        }
        match next {
            Work::LeaveProperty(key) => {
                active.remove(&key);
            }
            Work::Text(text) => {
                if result.len().checked_add(text.len())? > MAX_MAVEN_EXPANDED_VALUE_BYTES {
                    return None;
                }
                result.push_str(&text);
            }
            Work::Property(key) => {
                if !active.insert(key.clone()) {
                    return None;
                }
                let replacement = properties.get(&key)?.clone();
                work.push(Work::LeaveProperty(key));
                work.push(Work::Value(replacement));
            }
            Work::Value(value) => {
                let tokens = maven_value_tokens(&value)?;
                for token in tokens.into_iter().rev() {
                    match token {
                        MavenValueToken::Text(text) => {
                            work.push(Work::Text(text));
                        }
                        MavenValueToken::Property(key) => {
                            work.push(Work::Property(key));
                        }
                    }
                }
            }
        }
    }
    Some(result.trim().to_string())
}

pub enum MavenValueToken {
    Text(String),
    Property(String),
}

pub fn maven_value_tokens(value: &str) -> Option<Vec<MavenValueToken>> {
    let mut tokens = Vec::new();
    let mut remainder = value;
    while let Some(start) = remainder.find("${") {
        let text = &remainder[..start];
        if text.contains('}') {
            return None;
        }
        if !text.is_empty() {
            tokens.push(MavenValueToken::Text(text.to_string()));
        }
        let after_start = &remainder[start + 2..];
        let end = after_start.find('}')?;
        let key = after_start[..end].trim();
        if key.is_empty() {
            return None;
        }
        tokens.push(MavenValueToken::Property(key.to_string()));
        remainder = &after_start[end + 1..];
    }
    if remainder.contains("${") || remainder.contains('}') {
        return None;
    }
    if !remainder.is_empty() {
        tokens.push(MavenValueToken::Text(remainder.to_string()));
    }
    Some(tokens)
}

#[derive(Debug, Default)]
pub struct XmlNode {
    pub name: String,
    pub text: String,
    pub children: Vec<XmlNode>,
}

impl XmlNode {
    pub fn child<'a>(&'a self, name: &'a str) -> Option<&'a XmlNode> {
        self.children_named(name).next()
    }

    pub fn child_text<'a>(&'a self, name: &'a str) -> Option<&'a str> {
        self.child(name)
            .map(|child| child.text.trim())
            .filter(|text| !text.is_empty())
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a XmlNode> {
        self.children.iter().filter(move |child| child.name == name)
    }
}

pub fn parse_xml(source: &str) -> Option<XmlNode> {
    // No per-event trimming: quick-xml splits text at each entity or
    // character reference, so trimming each piece would delete the spaces
    // beside a reference. Readers trim a node's whole text instead.
    let mut reader = Reader::from_str(source);
    let mut stack = Vec::<XmlNode>::new();
    let mut root = None;
    let mut buffer = Vec::new();
    let mut nodes = 0usize;
    loop {
        match reader.read_event_into(&mut buffer).ok()? {
            Event::Start(start) => {
                nodes = nodes.checked_add(1)?;
                if nodes > MAX_MAVEN_XML_NODES || stack.len() >= MAX_MAVEN_XML_DEPTH {
                    return None;
                }
                stack.push(XmlNode {
                    name: local_xml_name(start.name().as_ref())?,
                    ..XmlNode::default()
                });
            }
            Event::Empty(empty) => {
                nodes = nodes.checked_add(1)?;
                if nodes > MAX_MAVEN_XML_NODES {
                    return None;
                }
                let node = XmlNode {
                    name: local_xml_name(empty.name().as_ref())?,
                    ..XmlNode::default()
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if root.replace(node).is_some() {
                    return None;
                }
            }
            Event::Text(text) => {
                let decoded = text.xml10_content().ok()?;
                let decoded = quick_xml::escape::unescape(&decoded).ok()?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&decoded);
                }
            }
            Event::CData(text) => {
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&text.decode().ok()?);
                }
            }
            // quick-xml reports `&amp;` and `&#45;` as their own events.
            Event::GeneralRef(reference) => {
                let reference = format!("&{};", reference.decode().ok()?);
                let decoded = quick_xml::escape::unescape(&reference).ok()?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&decoded);
                }
            }
            Event::End(_) => {
                let node = stack.pop()?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if root.replace(node).is_some() {
                    return None;
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    stack.is_empty().then_some(root).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn parse_xml_reads_namespaced_elements_and_decoded_text() {
        let source = r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- generated by a release tool -->
<m:project xmlns:m="http://maven.apache.org/POM/4.0.0">
  <m:description><![CDATA[uses <generics> & ampersands]]></m:description>
  <m:url>
     https://example.com/a
  </m:url>
  <m:modules>
    <m:module>a</m:module>
    <?ignored instruction?>
    <m:module/>
    <!-- b is the last module -->
    <m:module>b</m:module>
  </m:modules>
  <m:empty>   </m:empty>
</m:project>"#;
        let root = parse_xml(source).expect("well-formed XML");
        assert_eq!(root.name, "project");
        assert_eq!(
            root.child_text("description"),
            Some("uses <generics> & ampersands")
        );
        assert_eq!(root.child_text("url"), Some("https://example.com/a"));
        let modules = root.child("modules").expect("modules element");
        let names: Vec<_> = modules
            .children_named("module")
            .map(|module| module.text.as_str())
            .collect();
        assert_eq!(names, ["a", "", "b"]);
        assert_eq!(modules.child_text("module"), Some("a"));
        assert!(root.child("empty").is_some());
        assert_eq!(root.child_text("empty"), None);
        assert!(root.child("missing").is_none());
    }

    /// quick-xml reports `&amp;` and `&#NN;` as separate `GeneralRef`
    /// events, which `parse_xml` ignores, and text trimming then removes the
    /// spaces next to each reference.
    #[test]
    #[hardwon("4961f92aee92: parse_xml dropped entity and character references from element text")]
    fn parse_xml_decodes_entity_and_character_references() {
        let root = parse_xml(
            "<project><name>Tom &amp; Jerry</name>\
             <url>https://example.com/?a=1&amp;b=2</url>\
             <version>1.0&#45;SNAPSHOT</version></project>",
        )
        .expect("well-formed XML");
        assert_eq!(
            [
                root.child_text("name"),
                root.child_text("url"),
                root.child_text("version"),
            ],
            [
                Some("Tom & Jerry"),
                Some("https://example.com/?a=1&b=2"),
                Some("1.0-SNAPSHOT"),
            ]
        );
    }

    #[test]
    fn parse_xml_rejects_documents_without_exactly_one_closed_root() {
        for (label, source) in [
            ("empty document", ""),
            ("only a comment", "<!-- nothing -->"),
            (
                "mismatched end tag",
                "<project><groupId>g</artifactId></project>",
            ),
            ("unclosed child", "<project><groupId>g</project>"),
            ("unclosed root", "<project><groupId>g</groupId>"),
            ("stray end tag", "</project>"),
            ("two roots", "<project></project><project></project>"),
            ("empty second root", "<project></project><project/>"),
        ] {
            let parsed = parse_xml(source);
            assert!(parsed.is_none(), "{label}: {parsed:?}");
        }
        assert_eq!(
            parse_xml("<project/>").map(|root| root.name).as_deref(),
            Some("project")
        );
    }

    #[test]
    fn parse_xml_bounds_are_inclusive() {
        let nested = |depth: usize| format!("{}{}", "<n>".repeat(depth), "</n>".repeat(depth));
        assert!(parse_xml(&nested(MAX_MAVEN_XML_DEPTH)).is_some());
        assert!(parse_xml(&nested(MAX_MAVEN_XML_DEPTH + 1)).is_none());

        // The root plus empty children: every element counts as one node.
        let wide = |nodes: usize| format!("<r>{}</r>", "<c/>".repeat(nodes - 1));
        let root = parse_xml(&wide(MAX_MAVEN_XML_NODES)).expect("node count at the cap");
        assert_eq!(root.children.len(), MAX_MAVEN_XML_NODES - 1);
        assert!(parse_xml(&wide(MAX_MAVEN_XML_NODES + 1)).is_none());
    }

    #[test]
    fn project_properties_add_model_coordinates_with_parent_fallback() {
        let project = parse_xml(
            "<project>\
               <parent><groupId>parent.group</groupId><artifactId>parent-artifact</artifactId>\
                 <version>3.0</version></parent>\
               <artifactId>child</artifactId>\
               <properties>\
                 <java.release> 21 </java.release>\
                 <blank>  </blank>\
                 <nested><inner>x</inner></nested>\
                 <project.version>overridden</project.version>\
               </properties>\
             </project>",
        )
        .expect("well-formed XML");
        let mut expected = HashMap::default();
        for (key, value) in [
            ("java.release", "21"),
            ("project.groupId", "parent.group"),
            ("pom.groupId", "parent.group"),
            ("project.artifactId", "child"),
            ("pom.artifactId", "child"),
            // Maven resolves `project.*` from the model before user properties.
            ("project.version", "3.0"),
            ("pom.version", "3.0"),
        ] {
            expected.insert(key.to_owned(), value.to_owned());
        }
        assert_eq!(maven_project_properties(&project), expected);
    }

    #[test]
    fn property_expansion_resolves_nested_references_and_rejects_unresolvable_ones() {
        let mut properties = HashMap::default();
        let big = "x".repeat(MAX_MAVEN_EXPANDED_VALUE_BYTES / 2);
        for (key, value) in [
            ("version", "1.2.3"),
            ("a", "${b}"),
            ("b", "${c}"),
            ("c", "deep"),
            ("twice", "${version}/${version}"),
            ("self", "${self}"),
            ("x", "${y}"),
            ("y", "${x}"),
            ("refers.undefined", "${undefined}"),
            ("big", big.as_str()),
        ] {
            properties.insert(key.to_owned(), value.to_owned());
        }
        for (value, expected) in [
            ("plain text", Some("plain text")),
            ("  padded  ", Some("padded")),
            ("${a}", Some("deep")),
            ("v${version}-SNAPSHOT", Some("v1.2.3-SNAPSHOT")),
            ("${twice}+${twice}", Some("1.2.3/1.2.3+1.2.3/1.2.3")),
            ("${self}", None),
            ("${x}", None),
            ("${undefined}", None),
            ("pre-${refers.undefined}", None),
            ("${", None),
            ("${version", None),
            ("${}", None),
            ("${ }", None),
            ("version}", None),
            ("a}${version}", None),
            ("${version}}", None),
        ] {
            assert_eq!(
                expand_maven_value(value, &properties).as_deref(),
                expected,
                "{value:?}"
            );
        }
        let at_cap = expand_maven_value("${big}${big}", &properties).expect("value at the cap");
        assert_eq!(at_cap.len(), MAX_MAVEN_EXPANDED_VALUE_BYTES);
        assert_eq!(expand_maven_value("${big}${big}!", &properties), None);
    }
}
