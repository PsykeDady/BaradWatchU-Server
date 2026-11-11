//! Shared Client/Server presentation settings in the user's baradwatchu config folder.
use serde::Serialize;
use std::{fs, io::Write, path::{Path, PathBuf}};

#[derive(Debug)]
pub struct CliError(pub String);
pub fn state_dir() -> Result<PathBuf, CliError> {
    baradwatchu_messages::configuration_directory().ok_or_else(||CliError("Cannot locate configuration directory".into()))
}
pub fn output_json<T: Serialize>(value: &T) -> Result<String, CliError> {
    serde_json::to_string(value).map_err(|e|CliError(e.to_string()))
}
pub fn ensure_private_dir(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    fs::DirBuilder::new().recursive(true).mode(0o700).create(path).map_err(|e|CliError(e.to_string()))?;
    let m=fs::symlink_metadata(path).map_err(|e|CliError(e.to_string()))?;
    if !m.is_dir() || m.uid()!=unsafe{libc::geteuid()} {return Err(CliError("Unsafe configuration directory".into()));}
    Ok(())
}
pub fn atomic_json<T:Serialize>(path:&Path,value:&T)->Result<(),CliError> {
    use std::os::unix::fs::OpenOptionsExt;
    let bytes=serde_json::to_vec_pretty(value).map_err(|e|CliError(e.to_string()))?;
    let temp=path.with_extension(format!("{}.tmp",crate::storage::random().map_err(CliError)?));
    let result=(|| -> std::io::Result<()> {
        let mut file=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)?;
        file.write_all(&bytes)?;file.sync_all()?;fs::rename(&temp,path)?;
        if let Some(parent)=path.parent(){fs::File::open(parent)?.sync_all()?;}
        Ok(())
    })();
    if result.is_err(){let _=fs::remove_file(&temp);}
    result.map_err(|e|CliError(e.to_string()))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LanguageRequest {
    language: baradwatchu_messages::Language,
}

pub fn language_view() -> serde_json::Value {
    let language = baradwatchu_messages::configured_language();
    serde_json::json!({"language": language, "effectiveLanguage": language.effective().code(), "messages":baradwatchu_messages::server_dashboard_catalog(language)})
}

fn save_language_at(directory: &Path, request: LanguageRequest) -> Result<(), CliError> {
    ensure_private_dir(directory)?;
    atomic_json(&directory.join("language.json"), &baradwatchu_messages::LanguagePreference {
        schema_version: "baradwatchu.language.v1".into(),
        language: request.language,
    })
}

pub fn save_language(request: LanguageRequest) -> Result<serde_json::Value, CliError> {
    save_language_at(&state_dir()?, request)?;
    Ok(language_view())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn language_request_matches_client_contract() {
        for language in ["system", "italian", "english"] {
            assert!(serde_json::from_value::<LanguageRequest>(serde_json::json!({"language":language})).is_ok());
        }
        for value in [serde_json::json!({"language":"it"}), serde_json::json!({}), serde_json::json!({"language":"english","other":true})] {
            assert!(serde_json::from_value::<LanguageRequest>(value).is_err());
        }
    }
    #[test]
    fn language_file_is_client_compatible_and_private() {
        use std::os::unix::fs::PermissionsExt;
        let directory=std::env::temp_dir().join(format!("bwu-language-{}", crate::storage::random().unwrap()));
        save_language_at(&directory, LanguageRequest{language:baradwatchu_messages::Language::Italian}).unwrap();
        let file=directory.join("language.json");
        let saved:baradwatchu_messages::LanguagePreference=serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        assert_eq!(saved.schema_version,"baradwatchu.language.v1");
        assert_eq!(saved.language,baradwatchu_messages::Language::Italian);
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777,0o600);
        fs::remove_dir_all(directory).unwrap();
    }
}
