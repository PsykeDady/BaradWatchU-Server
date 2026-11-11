//! Client configuration.json contract and validation; never resolves or runs a tool.
use crate::report::{AuditReport, Priority, ResultStatus};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Component, Path},
};
const CHECK_SCHEMA: &str = "baradwatchu.custom-checks.v1";
const MAX_TIMEOUT_SECONDS: u64 = 300;
const MAX_PROVIDERS: usize = 16;
fn empty_parameters() -> serde_json::Value {
    serde_json::json!({})
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckConfiguration {
    pub schema_version: String,
    pub id: String,
    pub name: String,
    pub description: String,
    pub priority: Priority,
    pub enabled: bool,
    /// Single entry point; built-in controls may declare `providers` instead.
    #[serde(default)]
    pub tool_path: Option<String>,
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderConfiguration>,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default = "empty_parameters")]
    pub parameters: serde_json::Value,
    #[serde(default)]
    pub expected_sha256: Option<String>,
    #[serde(default)]
    pub version: Option<u64>,
    #[serde(default)]
    pub override_builtin_id: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderConfiguration {
    pub name: String,
    pub tool_path: String,
    #[serde(default = "empty_parameters")]
    pub parameters: serde_json::Value,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

fn valid_provider_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || (index > 0 && byte == b'-')
        })
}

/// `acceptedProviders` (mandatory providers) from requirement parameters: missing or empty
/// means "any one provider is enough". `providerParameters` may override provider defaults.
fn accepted_providers(
    parameters: &serde_json::Value,
    known: &[&str],
) -> Result<Vec<String>, String> {
    let accepted = match parameters.get("acceptedProviders") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(items)) => {
            let mut accepted = Vec::new();
            for item in items {
                let Some(id) = item.as_str() else {
                    return Err("acceptedProviders deve essere un elenco di ID provider".into());
                };
                if !known.contains(&id) {
                    return Err(format!(
                        "acceptedProviders contiene un provider sconosciuto: {id}"
                    ));
                }
                if !accepted.iter().any(|value| value == id) {
                    accepted.push(id.to_owned());
                }
            }
            accepted
        }
        Some(_) => return Err("acceptedProviders deve essere un elenco di ID provider".into()),
    };
    match parameters.get("providerParameters") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Object(map)) => {
            for (id, value) in map {
                if !known.contains(&id.as_str()) {
                    return Err(format!(
                        "providerParameters contiene un provider sconosciuto: {id}"
                    ));
                }
                if !value.is_object() {
                    return Err(format!(
                        "providerParameters.{id} deve essere un oggetto JSON"
                    ));
                }
            }
        }
        Some(_) => return Err("providerParameters deve essere un oggetto JSON".into()),
    }
    Ok(accepted)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validate one parsed `configuration.json`; the message is shown to the user as-is.
fn validate_configuration(folder: &str, config: &CheckConfiguration) -> Result<(), String> {
    if config.schema_version != CHECK_SCHEMA {
        return Err(format!("schemaVersion deve essere \"{CHECK_SCHEMA}\""));
    }
    if config.id != folder {
        return Err(format!(
            "id \"{}\" diverso dal nome della cartella \"{folder}\"",
            config.id
        ));
    }
    if config.name.trim().is_empty() || config.name.len() > 160 {
        return Err("name è obbligatorio (massimo 160 caratteri)".into());
    }
    if config.description.len() > 2048 {
        return Err("description supera 2048 caratteri".into());
    }
    if !config.parameters.is_object() {
        return Err("parameters deve essere un oggetto JSON".into());
    }
    if config.arguments.len() > 64 || config.arguments.iter().any(|arg| arg.len() > 4096) {
        return Err("arguments ammette al massimo 64 stringhe di 4096 caratteri".into());
    }
    match (&config.tool_path, config.providers.is_empty()) {
        (Some(path), true) if safe_relative_path(path) => {}
        (Some(_), true) => {
            return Err(
                "toolPath deve essere un percorso relativo alla cartella del controllo (es. ./check.sh)"
                    .into(),
            )
        }
        // Configuration-only override: reuses the official files of the built-in it replaces.
        (None, true) if config.override_builtin_id.is_some() => {
            if config.expected_sha256.is_some() || !config.arguments.is_empty() {
                return Err(
                    "un override di sola configurazione non dichiara expectedSha256 né arguments"
                        .into(),
                );
            }
        }
        (None, true) => {
            return Err(
                "toolPath è obbligatorio (oppure overrideBuiltinId per un override di sola configurazione)"
                    .into(),
            )
        }
        (Some(_), false) => return Err("toolPath e providers sono alternativi".into()),
        (None, false) => {
            if config.providers.len() > MAX_PROVIDERS {
                return Err(format!("providers ammette al massimo {MAX_PROVIDERS} voci"));
            }
            if config.expected_sha256.is_some() {
                return Err("un controllo con providers non dichiara expectedSha256".into());
            }
            for (id, provider) in &config.providers {
                if !valid_provider_id(id) {
                    return Err(format!(
                        "ID provider non valido: {id} (minuscole, cifre e trattini)"
                    ));
                }
                if provider.name.trim().is_empty() || provider.name.len() > 160 {
                    return Err(format!("providers.{id}.name è obbligatorio (massimo 160 caratteri)"));
                }
                if !safe_relative_path(&provider.tool_path) {
                    return Err(format!(
                        "providers.{id}.toolPath deve essere un percorso relativo alla cartella del controllo"
                    ));
                }
                if !provider.parameters.is_object() {
                    return Err(format!("providers.{id}.parameters deve essere un oggetto JSON"));
                }
                if provider
                    .timeout_seconds
                    .is_some_and(|value| value == 0 || value > MAX_TIMEOUT_SECONDS)
                {
                    return Err(format!(
                        "timeoutSeconds deve essere compreso tra 1 e {MAX_TIMEOUT_SECONDS}"
                    ));
                }
            }
            let known = config.providers.keys().map(String::as_str).collect::<Vec<_>>();
            accepted_providers(&config.parameters, &known)?;
        }
    }
    if config
        .timeout_seconds
        .is_some_and(|value| value == 0 || value > MAX_TIMEOUT_SECONDS)
    {
        return Err(format!(
            "timeoutSeconds deve essere compreso tra 1 e {MAX_TIMEOUT_SECONDS}"
        ));
    }
    if config
        .expected_sha256
        .as_deref()
        .is_some_and(|hash| !valid_sha256(hash))
    {
        return Err("expectedSha256 deve contenere 64 cifre esadecimali".into());
    }
    Ok(())
}
fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.as_os_str().is_empty()
        && !value.contains("//")
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

impl CheckConfiguration {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.len() > 64
            || self.id == "REQ-"
            || self.id == "CUSTOM-"
            || !(self.id.starts_with("REQ-") || self.id.starts_with("CUSTOM-"))
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("invalid requirement ID".into());
        }
        if let Some(id) = &self.override_builtin_id {
            if !self.id.starts_with("CUSTOM-")
                || !id.starts_with("REQ-")
                || id.len() > 64
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err("invalid overrideBuiltinId".into());
            }
        }
        validate_configuration(&self.id, self)
    }
    pub fn compare(&self, report: &AuditReport) -> serde_json::Value {
        let result_id = self.override_builtin_id.as_deref().unwrap_or(&self.id);
        let result = report.results.iter().find(|r| r.id == result_id);
        let enabled = result.map(|r| r.status != ResultStatus::Disabled);
        let priority = result.map(|r| r.priority);
        let provenance = result.and_then(|r| r.provenance.as_ref());
        let hash = provenance.and_then(|p| p.actual_sha256.as_deref());
        let hash_state = match (self.expected_sha256.as_deref(), hash) {
            (Some(expected), Some(actual)) => {
                if expected.eq_ignore_ascii_case(actual) {
                    "MATCH"
                } else {
                    "MISMATCH"
                }
            }
            _ => "UNKNOWN",
        };
        let metadata_state = if result.is_none() {
            "MISSING"
        } else if enabled != Some(self.enabled)
            || priority != Some(self.priority)
            || provenance
                .is_some_and(|p| self.override_builtin_id.is_some() && p.tool_id != self.id)
        {
            "MISMATCH"
        } else {
            "MATCH"
        };
        serde_json::json!({"id":self.id,"resultId":result_id,"name":self.name,"enabled":self.enabled,"reportedEnabled":enabled,"priority":self.priority,"reportedPriority":priority,"metadataState":metadata_state,"expectedSha256":self.expected_sha256,"reportedSha256":hash,"hashState":hash_state,"parametersState":"UNKNOWN"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    fn sample() -> CheckConfiguration {
        serde_json::from_value(json!({"schemaVersion":CHECK_SCHEMA,"id":"CUSTOM-001","name":"Test","description":"","priority":"HIGH","enabled":true,"toolPath":"./check.sh","expectedSha256":"a".repeat(64)})).unwrap()
    }
    #[test]
    fn client_catalog_definitions_validate_and_roundtrip() {
        // Snapshot of all nine Client catalog configurations, including providers.
        let fixtures: Vec<Value> = serde_json::from_str(include_str!(
            "../tests/fixtures/client-check-configurations.json"
        ))
        .unwrap();
        assert_eq!(fixtures.len(), 9);
        for fixture in fixtures {
            let config: CheckConfiguration = serde_json::from_value(fixture.clone()).unwrap();
            config.validate().unwrap();
            let encoded = serde_json::to_value(&config).unwrap();
            fn preserves(got: &Value, original: &Value) {
                if let Some(object) = original.as_object() {
                    for (key, value) in object {
                        preserves(&got[key], value);
                    }
                } else {
                    assert_eq!(got, original);
                }
            }
            preserves(&encoded, &fixture);
            let decoded: CheckConfiguration = serde_json::from_value(encoded).unwrap();
            decoded.validate().unwrap();
        }
    }
    #[test]
    fn configuration_only_override_and_provider_constraints_match_client() {
        let mut config = sample();
        config.tool_path = None;
        config.expected_sha256 = None;
        config.override_builtin_id = Some("REQ-001".into());
        config.validate().unwrap();
        config.expected_sha256 = Some("a".repeat(64));
        assert!(config.validate().is_err());
        config = sample();
        config.tool_path = Some("../outside.sh".into());
        assert!(config.validate().is_err());
        config = sample();
        config.timeout_seconds = Some(301);
        assert!(config.validate().is_err());
        config = sample();
        config.parameters = json!([]);
        assert!(config.validate().is_err());
        config = sample();
        config.tool_path = None;
        config.expected_sha256 = None;
        config.providers.insert(
            "first".into(),
            ProviderConfiguration {
                name: "First".into(),
                tool_path: "./first.sh".into(),
                parameters: json!({}),
                timeout_seconds: Some(30),
            },
        );
        config.parameters = json!({"acceptedProviders":["missing"]});
        assert!(config.validate().is_err());
        config.parameters = json!({"acceptedProviders":["first"]});
        config.validate().unwrap();
    }
    #[test]
    fn definition_persistence_replaces_by_id_without_creating_identity() {
        let store = crate::storage::Store::memory();
        let mut config = sample();
        store.save_requirement_definition(&config).unwrap();
        config.enabled = false;
        config.parameters = json!({"limit":7});
        store.save_requirement_definition(&config).unwrap();
        let saved = store.requirement_definitions().unwrap();
        assert_eq!(saved.len(), 1);
        assert!(!saved[0].enabled);
        assert_eq!(saved[0].parameters["limit"], 7);
        assert!(store.identity().unwrap().is_none());
        config.tool_path = Some("/tmp/check".into());
        assert!(store.save_requirement_definition(&config).is_err());
        assert_eq!(
            store.requirement_definitions().unwrap()[0]
                .tool_path
                .as_deref(),
            Some("./check.sh")
        );
        store.remove_requirement_definition(&config.id).unwrap();
        assert!(store.requirement_definitions().unwrap().is_empty());
    }
    #[test]
    fn compares_metadata_and_hash_but_never_invents_parameter_evidence() {
        let mut config = sample();
        let mut report:AuditReport=serde_json::from_value(json!({"schemaVersion":"baradwatchu.audit.v1","completedAtUnixMs":1,"results":[{"id":"CUSTOM-001","name":"Test","priority":"HIGH","status":"PASS","summary":"ok","details":[],"completedAtUnixMs":1}]})).unwrap();
        let compared = config.compare(&report);
        assert_eq!(compared["metadataState"], "MATCH");
        assert_eq!(compared["hashState"], "UNKNOWN");
        assert_eq!(compared["parametersState"], "UNKNOWN");
        config.enabled = false;
        assert_eq!(config.compare(&report)["metadataState"], "MISMATCH");
        report.results[0].status = ResultStatus::Disabled;
        assert_eq!(config.compare(&report)["metadataState"], "MATCH");
        report.results.clear();
        assert_eq!(config.compare(&report)["metadataState"], "MISSING");
    }
}
