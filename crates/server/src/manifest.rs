//! Client builtin-tools.sha256 shipped as the paired baseline, with an optional admin override.
use crate::report::{AuditReport, FileState, IntegrityStatus};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const BUNDLED_CLIENT_MANIFEST: &str =
    include_str!("../client-catalog/catalog/builtin-tools.sha256");

pub fn bundled_client_version() -> &'static str {
    include_str!("../client-catalog/client-version.txt").trim()
}

pub fn default_text() -> &'static str {
    BUNDLED_CLIENT_MANIFEST
}

#[derive(Debug)]
pub struct Entry {
    pub requirement: String,
    pub platform: String,
    pub path: String,
    pub sha256: String,
}
pub fn parse(text: &str) -> Result<Vec<Entry>, String> {
    if text.len() > 2 * 1024 * 1024 {
        return Err("manifest exceeds 2 MiB".into());
    }
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 4 {
            return Err(format!("invalid manifest line {}", index + 1));
        }
        let [id, platform, path, hash] = [f[0], f[1], f[2], f[3]];
        let folder = if platform == "windows" {
            "checks-windows"
        } else {
            "checks"
        };
        let prefix = format!("catalog/{folder}/{id}/");
        if !id.starts_with("REQ-")
            || id.len() < 5
            || id.len() > 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
            || !matches!(platform, "linux" | "windows")
            || !path.starts_with(&prefix)
            || path.len() <= prefix.len()
            || path.contains('\\')
            || path
                .split('/')
                .any(|s| s.is_empty() || s == "." || s == "..")
            || hash.len() != 64
            || !hash.bytes().all(|b| b.is_ascii_hexdigit())
            || !seen.insert((platform.to_owned(), path.to_owned()))
        {
            return Err(format!(
                "unsafe, duplicate or invalid manifest line {}",
                index + 1
            ));
        }
        result.push(Entry {
            requirement: id.into(),
            platform: platform.into(),
            path: path.into(),
            sha256: hash.to_ascii_lowercase(),
        });
    }
    if result.is_empty() {
        return Err("empty manifest".into());
    }
    Ok(result)
}
pub fn digest(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}
pub fn view(text: &str, source: &str) -> Result<Value, String> {
    let entries = parse(text)?;
    Ok(json!({
        "text": text,
        "sha256": digest(text),
        "files": entries.len(),
        "platforms": entries.iter().map(|e| e.platform.as_str()).collect::<BTreeSet<_>>(),
        "source": source,
        "clientVersion": (source == "bundled").then(bundled_client_version),
        "entries": entries.iter().map(|e| json!({"requirementId":e.requirement,"platform":e.platform,"path":e.path,"sha256":e.sha256})).collect::<Vec<_>>()
    }))
}
pub fn compare(text: &str, report: &AuditReport) -> Result<Value, String> {
    compare_with_digest(text, None, report)
}
pub fn compare_with_digest(
    text: &str,
    digest_override: Option<&str>,
    report: &AuditReport,
) -> Result<Value, String> {
    let entries = parse(text)?;
    let Some(installation) = &report.installation else {
        return Ok(json!({"state":"UNKNOWN","manifestState":"UNKNOWN","files":[]}));
    };
    let expected_digest = digest_override
        .map(str::to_owned)
        .unwrap_or_else(|| digest(text));
    let expected: Vec<_> = entries
        .iter()
        .filter(|e| e.platform == installation.platform)
        .collect();
    if expected.is_empty() {
        return Ok(
            json!({"state":"UNKNOWN","manifestState":"UNKNOWN","expectedManifestSha256":expected_digest,"reportedManifestSha256":installation.manifest_sha256,"files":[],"platform":installation.platform}),
        );
    }
    let mut seen = BTreeMap::new();
    let mut duplicate = false;
    for file in &installation.files {
        if seen.insert(file.path.as_str(), file).is_some() {
            duplicate = true;
        }
    }
    let mut files = Vec::new();
    for entry in &expected {
        let reported = seen.remove(entry.path.as_str());
        let state = match reported {
            None => "MISSING",
            Some(f) if f.requirement_id != entry.requirement => "MISMATCH",
            Some(f) if f.actual_sha256.as_deref().is_none() => "UNKNOWN",
            Some(f)
                if !f
                    .actual_sha256
                    .as_ref()
                    .unwrap()
                    .eq_ignore_ascii_case(&entry.sha256) =>
            {
                "MISMATCH"
            }
            Some(f) if f.state != FileState::Verified => "UNVERIFIED",
            Some(_) => "MATCH",
        };
        let declared = match reported.and_then(|f| f.expected_sha256.as_deref()) {
            None => "UNKNOWN",
            Some(h) if h.eq_ignore_ascii_case(&entry.sha256) => "MATCH",
            Some(_) => "MISMATCH",
        };
        files.push(json!({"id":entry.requirement,"path":entry.path,"expectedSha256":entry.sha256,"reportedSha256":reported.and_then(|f|f.actual_sha256.as_ref()),"state":state,"declaredExpectationState":declared}));
    }
    for file in seen.values() {
        files.push(json!({"id":file.requirement_id,"path":file.path,"state":"UNEXPECTED","declaredExpectationState":"UNKNOWN"}));
    }
    let manifest_state = if expected_digest.eq_ignore_ascii_case(&installation.manifest_sha256) {
        "MATCH"
    } else {
        "MISMATCH"
    };
    let verified = installation
        .files
        .iter()
        .filter(|f| f.state == FileState::Verified)
        .count();
    let summary_coherent = installation.verified_files == verified
        && (installation.status == IntegrityStatus::Verified)
            == (verified == installation.files.len() && verified > 0);
    let state = if duplicate || !summary_coherent {
        "INCONSISTENT"
    } else if manifest_state == "MATCH"
        && files
            .iter()
            .all(|f| f["state"] == "MATCH" && f["declaredExpectationState"] == "MATCH")
    {
        "MATCH"
    } else {
        "UNVERIFIED"
    };
    Ok(
        json!({"state":state,"manifestState":manifest_state,"expectedManifestSha256":expected_digest,"reportedManifestSha256":installation.manifest_sha256,"platform":installation.platform,"files":files}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const FIXTURE: &str = include_str!("../tests/fixtures/client-builtin-tools.sha256");
    fn sample() -> (String, AuditReport) {
        let hash = "a".repeat(64);
        let text = format!("REQ-001 linux catalog/checks/REQ-001/check.sh {hash}\n");
        let report=serde_json::from_value(json!({"schemaVersion":"baradwatchu.audit.v1","completedAtUnixMs":1,"results":[],"installation":{"status":"VERIFIED","platform":"linux","manifestSha256":digest(&text),"verifiedFiles":1,"files":[{"requirementId":"REQ-001","path":"catalog/checks/REQ-001/check.sh","expectedSha256":hash,"actualSha256":hash,"state":"VERIFIED"}]}})).unwrap();
        (text, report)
    }
    #[test]
    fn client_manifest_parses_and_persists_exact_bytes() {
        let entries = parse(FIXTURE).unwrap();
        assert!(entries.len() > 20);
        let store = crate::storage::Store::memory();
        assert!(store.expected_manifest().unwrap().is_none());
        store.save_expected_manifest(FIXTURE).unwrap();
        assert_eq!(store.expected_manifest().unwrap().as_deref(), Some(FIXTURE));
        assert!(store.save_expected_manifest("invalid").is_err());
        assert_eq!(store.expected_manifest().unwrap().as_deref(), Some(FIXTURE));
        store.remove_expected_manifest().unwrap();
        assert!(store.expected_manifest().unwrap().is_none());
    }
    #[test]
    fn rejects_duplicates_traversal_wrong_id_and_invalid_hash() {
        let (text, _) = sample();
        assert!(parse(&(text.clone() + &text)).is_err());
        for invalid in [
            text.replace("/check.sh", "/../check.sh"),
            text.replace("REQ-001/check", "REQ-002/check"),
            text.replace(&"a".repeat(64), "oops"),
            text.replace(" linux ", " any "),
        ] {
            assert!(parse(&invalid).is_err());
        }
    }
    #[test]
    fn compares_independent_hash_and_declared_expectation() {
        let (text, mut report) = sample();
        assert_eq!(compare(&text, &report).unwrap()["state"], "MATCH");
        let file = &mut report.installation.as_mut().unwrap().files[0];
        file.actual_sha256 = Some("b".repeat(64));
        file.expected_sha256 = Some("b".repeat(64));
        let result = compare(&text, &report).unwrap();
        assert_ne!(result["state"], "MATCH");
        assert_eq!(result["files"][0]["state"], "MISMATCH");
        assert_eq!(result["files"][0]["declaredExpectationState"], "MISMATCH");
    }
    #[test]
    fn missing_extra_duplicate_and_historical_evidence_never_match() {
        let (text, mut report) = sample();
        report.installation.as_mut().unwrap().files.clear();
        assert_eq!(
            compare(&text, &report).unwrap()["files"][0]["state"],
            "MISSING"
        );
        let (_, mut report) = sample();
        let file = report.installation.as_ref().unwrap().files[0].clone();
        report.installation.as_mut().unwrap().files.push(file);
        assert_eq!(compare(&text, &report).unwrap()["state"], "INCONSISTENT");
        report.installation.as_mut().unwrap().files[1].path =
            "catalog/checks/REQ-001/extra.sh".into();
        assert_eq!(
            compare(&text, &report).unwrap()["files"][1]["state"],
            "UNEXPECTED"
        );
        report.installation = None;
        assert_eq!(compare(&text, &report).unwrap()["state"], "UNKNOWN");
    }
    #[test]
    fn byte_level_manifest_hash_and_platform_are_distinct_from_file_match() {
        let (text, mut report) = sample();
        let result = compare(&(text + "\n"), &report).unwrap();
        assert_eq!(result["manifestState"], "MISMATCH");
        assert_eq!(result["files"][0]["state"], "MATCH");
        report.installation.as_mut().unwrap().platform = "windows".into();
        assert_eq!(compare(FIXTURE, &report).unwrap()["state"], "UNVERIFIED");
    }
}
