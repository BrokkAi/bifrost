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
    let mut reader = Reader::from_str(source);
    reader.config_mut().trim_text(true);
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
