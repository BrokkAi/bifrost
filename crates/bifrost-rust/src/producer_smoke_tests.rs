use crate::declarations::parse_rust_file;
use brokk_bifrost_core::analyzer::ProjectFile;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};

#[test]
#[ignore = "requires BIFROST_SMOKE_CORPORA checkout roots"]
fn rust_producer_corpus_smoke() {
    let roots = std::env::var_os("BIFROST_SMOKE_CORPORA")
        .expect("set BIFROST_SMOKE_CORPORA to checkout roots");
    let mut total = 0;
    for root in std::env::split_paths(&roots) {
        let root = root.canonicalize().expect("smoke corpus root exists");
        // Bound live ParsedFiles, independently of Cargo build concurrency.
        let workers = std::thread::available_parallelism().unwrap().get().min(8);
        let (send, receive) = mpsc::sync_channel::<std::path::PathBuf>(workers * 2);
        let receive = Mutex::new(receive);
        let failure = Mutex::new(None::<String>);
        let count = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..workers {
                let (root, receive, failure, count) = (&root, &receive, &failure, &count);
                handles.push(scope.spawn(move || {
                        let mut parser = tree_sitter::Parser::new();
                        parser.set_language(&tree_sitter_rust::LANGUAGE.into()).unwrap();
                        loop {
                            let Ok(path) = receive.lock().unwrap().recv() else { break; };
                            // Keep draining the bounded channel after the first
                            // failure, so its producer cannot be stranded in send.
                            if failure.lock().unwrap().is_some() { continue; }
                            let file = ProjectFile::new(root.clone(), path.strip_prefix(root).unwrap());
                            let mut source_bytes = 0;
                            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                let source = std::fs::read_to_string(&path).expect("read Rust smoke source");
                                source_bytes = source.len();
                                let tree = parser.parse(&source, None).expect("parse Rust smoke source");
                                // The coordinated walk owns RustResolutionBuilder
                                // and calls finish before returning ParsedFile.
                                parse_rust_file(&file, &source, &tree);
                            }));
                            match outcome {
                                Ok(()) => { count.fetch_add(1, Ordering::Relaxed); }
                                Err(payload) => {
                                    let message = payload.downcast_ref::<String>().map(String::as_str)
                                        .or_else(|| payload.downcast_ref::<&str>().copied())
                                        .unwrap_or("non-string panic payload");
                                    failure.lock().unwrap().get_or_insert_with(|| format!(
                                        "Rust producer smoke failed at {file:?}, source bytes 0..{}: {message}", source_bytes));
                                }
                            }
                        }
                    }));
            }
            let mut pending = vec![root.clone()];
            'directories: while let Some(directory) = pending.pop() {
                for entry in std::fs::read_dir(&directory).expect("read smoke directory") {
                    if failure.lock().unwrap().is_some() {
                        break 'directories;
                    }
                    let entry = entry.expect("read smoke entry");
                    let ty = entry.file_type().expect("read smoke file type");
                    let path = entry.path();
                    if ty.is_dir() {
                        pending.push(path);
                    } else if ty.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
                        send.send(path).expect("smoke workers remain connected");
                    }
                }
            }
            drop(send);
            for handle in handles {
                handle.join().expect("smoke worker joined");
            }
        });
        let count = count.into_inner();
        total += count;
        eprintln!(
            "Rust producer smoke: {count} files in {} ({total} total)",
            root.display()
        );
        if let Some(failure) = failure.into_inner().unwrap() {
            panic!("{failure}; {total} files completed before failure");
        }
    }
    assert!(total > 0, "smoke corpora contain Rust source files");
    eprintln!("Rust producer smoke: {total} files passed");
}
