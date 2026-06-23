/// Test fixture repository that stores only the most recently saved name.
pub struct MemoryRepository {
    saved_name: String,
}

impl Default for MemoryRepository {
    fn default() -> Self {
        Self {
            saved_name: String::new(),
        }
    }
}

impl MemoryRepository {
    pub fn save(&mut self, name: &str) {
        self.saved_name = name.trim().to_string();
    }
}

pub struct Service {
    repository: MemoryRepository,
}

impl Service {
    pub fn new(repository: MemoryRepository) -> Self {
        Self { repository }
    }

    pub fn execute(&self, suffix: &str) -> String {
        format!("{}{}", self.repository.saved_name, suffix.trim())
    }
}

pub fn build_service(repository: MemoryRepository) -> Service {
    Service::new(repository)
}
