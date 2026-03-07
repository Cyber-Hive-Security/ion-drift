use std::fs;
use std::path::{Path, PathBuf};

pub fn read_repo_file(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

pub fn source_paths_under(dir: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(dir);
    if let Ok(entries) = fs::read_dir(base) {
        for ent in entries.flatten() {
            let path = ent.path();
            if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out
}
