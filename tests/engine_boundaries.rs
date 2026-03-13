use std::fs;
use std::path::PathBuf;

const FORBIDDEN_PATTERNS: [(&str, &str); 10] = [
    ("std::time", "std::time"),
    ("std::fs", "std::fs"),
    ("std::net", "std::net"),
    ("rand", "rand"),
    ("HashMap", "HashMap"),
    ("HashSet", "HashSet"),
    ("tracing", "tracing"),
    ("std::env", "std::env"),
    ("log use", "use log::"),
    ("log path", "log::"),
];

#[test]
fn engine_modules_do_not_import_or_use_forbidden_dependencies() {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("src/engine");

    for entry in fs::read_dir(dir).expect("engine directory exists") {
        let entry = entry.expect("engine entry readable");
        let path = entry.path();
        let is_file = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext == "rs");
        if !is_file {
            continue;
        }

        let content = fs::read_to_string(&path).expect("engine source readable");
        for (_name, needle) in FORBIDDEN_PATTERNS {
            assert!(
                !contains_non_comment_reference(&content, needle),
                "forbidden token `{}` found in {}",
                needle,
                path.display()
            );
        }
    }
}

fn contains_non_comment_reference(content: &str, needle: &str) -> bool {
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("//!") {
            continue;
        }

        if trimmed.contains(needle) {
            return true;
        }
    }

    false
}
