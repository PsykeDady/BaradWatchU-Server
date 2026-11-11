use std::{env, fs, path::Path};

fn collect(root: &Path, current: &Path, files: &mut Vec<String>) {
    let mut entries = fs::read_dir(current)
        .expect("read bundled Client catalog")
        .map(|entry| entry.expect("read Client catalog entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect(root, &path, files);
        } else if path.is_file() {
            files.push(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.join("client-catalog");
    let mut files = Vec::new();
    collect(&root, &root, &mut files);
    let mut generated = String::from("&[\n");
    for relative in files {
        generated.push_str(&format!(
            "    ({relative:?}, include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/client-catalog/{relative}\"))),\n"
        ));
    }
    generated.push_str("]\n");
    fs::write(
        Path::new(&env::var("OUT_DIR").expect("OUT_DIR")).join("client_catalog_files.rs"),
        generated,
    )
    .expect("write generated Client catalog index");
    println!("cargo:rerun-if-changed=client-catalog");
}
