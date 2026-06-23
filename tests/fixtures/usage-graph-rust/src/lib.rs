pub mod consumer;
pub mod facade;
pub mod service;
pub mod util;

pub use facade::{MemoryRepository, Service, make_service};

pub fn run_demo() -> String {
    let mut repository = MemoryRepository::default();
    repository.save("Ada");
    let service = make_service(repository);
    service.execute(" Grace ")
}
