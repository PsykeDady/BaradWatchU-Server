//! Read-only, embedded Client source snapshot matching the bundled manifest.
static FILES: &[(&str, &[u8])] = include!(concat!(env!("OUT_DIR"), "/client_catalog_files.rs"));

pub fn file(path: &str) -> Option<&'static [u8]> {
    FILES
        .iter()
        .find(|(name, _)| *name == path)
        .map(|(_, bytes)| *bytes)
}
