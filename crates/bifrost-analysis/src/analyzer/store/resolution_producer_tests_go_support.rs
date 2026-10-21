#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod go_extraction_support_10 {

    use std::path::PathBuf;

    #[doc(hidden)]
    pub fn fixture_project_root(name: &str) -> PathBuf {
        std::env::current_dir()
            .expect("current directory is available for an absolute fixture root")
            .join(name)
    }
}
