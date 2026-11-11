//! Server-side custom check catalog and portable Client import package validation.
//! The Server stores and exports these files; it never executes them.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_TOOL_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomCheck {
    pub id: String,
    pub name: String,
    pub description: String,
    pub priority: crate::report::Priority,
    #[serde(default = "enabled")]
    pub enabled: bool,
    pub file_name: String,
    pub file_base64: String,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

fn enabled() -> bool {
    true
}

impl CustomCheck {
    pub fn validate(&self) -> Result<Vec<u8>, String> {
        if !self.id.starts_with("CUSTOM-")
            || self.id.len() <= 7
            || self.id.len() > 64
            || !self.id[7..]
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(
                "ID custom non valido: usa CUSTOM- seguito da lettere maiuscole, cifre o trattini"
                    .into(),
            );
        }
        if self.name.trim().is_empty() || self.name.len() > 160 || self.description.len() > 2048 {
            return Err(
                "Il nome è obbligatorio (massimo 160 caratteri); descrizione massima 2048".into(),
            );
        }
        if self.file_name.is_empty()
            || self.file_name.len() > 255
            || self.file_name.starts_with('.')
            || self.file_name == "configuration.json"
            || self.file_name.contains(['/', '\\', '\0'])
        {
            return Err("Nome del file tool non valido".into());
        }
        if self.arguments.len() > 64 || self.arguments.iter().any(|arg| arg.len() > 4096) {
            return Err("Troppi argomenti o argomenti troppo lunghi".into());
        }
        if self
            .timeout_seconds
            .is_some_and(|value| !(1..=300).contains(&value))
        {
            return Err("Il timeout deve essere compreso tra 1 e 300 secondi".into());
        }
        let bytes = STANDARD
            .decode(&self.file_base64)
            .map_err(|_| "Contenuto tool Base64 non valido")?;
        if bytes.is_empty() || bytes.len() > MAX_TOOL_BYTES {
            return Err("Il file tool deve contenere da 1 byte a 1 MiB".into());
        }
        Ok(bytes)
    }

    pub fn tool_sha256(&self) -> Result<String, String> {
        let bytes = self.validate()?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn public_view(&self) -> Result<serde_json::Value, String> {
        Ok(serde_json::json!({
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "priority": self.priority,
            "enabled": self.enabled,
            "fileName": self.file_name,
            "toolSha256": self.tool_sha256()?,
            "timeoutSeconds": self.timeout_seconds,
        }))
    }
}
