//! Read-only Client audit contract, copied from Client requirements.rs. No audit runner.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultStatus {
    Pass,
    Fail,
    Warn,
    Error,
    Disabled,
    NotApplicable,
}

impl std::fmt::Display for ResultStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Disabled => "DISABLED",
            Self::NotApplicable => "NOT_APPLICABLE",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Priority {
    Highest,
    High,
    Medium,
    Low,
    Optional,
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Highest => "HIGHEST",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Optional => "OPTIONAL",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlOrigin {
    #[default]
    Builtin,
    Custom,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityStatus {
    Verified,
    Mismatch,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlProvenance {
    pub tool_id: String,
    pub tool_version: Option<u64>,
    pub origin: ControlOrigin,
    pub tool_path: Option<String>,
    pub expected_sha256: Option<String>,
    pub actual_sha256: Option<String>,
    pub integrity_status: IntegrityStatus,
    pub integrity_scope: String,
    pub is_override: bool,
    pub override_builtin_id: Option<String>,
    pub builtin_tool_path: Option<String>,
    pub builtin_expected_sha256: Option<String>,
    /// The override changes only enabled/priority/parameters; the official files ran.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub configuration_override: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultRecord {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    pub priority: Priority,
    pub status: ResultStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_status: Option<ResultStatus>,
    pub summary: String,
    pub details: Vec<String>,
    pub completed_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ControlProvenance>,
}

/// Missing in historical reports: leave unknown instead of inventing an origin.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "origin", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditInitiator {
    Local,
    #[serde(rename_all = "camelCase")]
    Remote {
        operator_display_name: Option<String>,
        server_id: String,
        server_display_name: String,
        server_trusted_name: String,
        server_fingerprint: String,
    },
    /// Periodic audit started by the Client service under its local Barad Policy.
    Scheduled,
}

/// Barad Policy reported by the Client (state and SHA-256 of the bytes it read).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyReport {
    pub state: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditReport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator: Option<AuditInitiator>,
    pub schema_version: String,
    pub completed_at_unix_ms: u64,
    pub results: Vec<ResultRecord>,
    /// Hash of the running agent executable. Older cached reports may omit it.
    #[serde(default)]
    pub client: ClientIdentity,
    /// Reserved report extensions: PDF status and future policy features.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdf: Option<PdfArtifact>,
    #[serde(default)]
    pub extensions: AuditExtensions,
    /// Hash of every installed built-in check file compared with the manifest embedded in the
    /// agent, computed at audit time (for the Server's installation check). Older reports omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation: Option<InstallationIntegrity>,
    /// Barad Policy state and SHA-256 (Client 2026-11 and later). Older reports omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallationIntegrity {
    /// VERIFIED when every listed file matches; MISMATCH otherwise.
    pub status: IntegrityStatus,
    pub platform: String,
    /// SHA-256 of the manifest embedded in the running agent.
    pub manifest_sha256: String,
    pub verified_files: usize,
    pub files: Vec<InstalledFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledFile {
    pub requirement_id: String,
    /// Relative to the installed data root, e.g. `catalog/checks/REQ-002/providers/clamav.sh`.
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_sha256: Option<String>,
    pub state: FileState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileState {
    Verified,
    Modified,
    Missing,
    /// Present in a built-in check folder but not in the manifest.
    Unexpected,
    /// Symbolic link, special file or oversized file where a regular file is expected.
    Unsafe,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientIdentity {
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfArtifact {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditExtensions {
    /// Future per-machine exceptions; current DISABLED results remain represented in results.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_requirements: Vec<DisabledRequirement>,
    /// Per-provider results of provider-based requirements (`required` = listed in acceptedProviders).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<ProviderResult>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisabledRequirement {
    pub id: String,
    pub priority: Priority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderResult {
    pub requirement_id: String,
    pub provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub origin: ControlOrigin,
    pub required: bool,
    pub status: ResultStatus,
    pub summary: String,
    #[serde(default)]
    pub details: Vec<String>,
}
