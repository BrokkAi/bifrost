#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceContent {
    text: String,
}

impl SourceContent {
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn into_string(self) -> String {
        self.text
    }
}
