//! Validate Client observations without claiming independent proof of execution.
use crate::{report::*, storage::RequirementBaseline};
use serde_json::{json, Value};
use std::collections::HashSet;

pub fn parse(value: &Value) -> Result<AuditReport, String> {
    let report: AuditReport = serde_json::from_value(value.clone())
        .map_err(|e| format!("INVALID_CLIENT_REPORT: {e}"))?;
    if report.schema_version != "baradwatchu.audit.v1" { return Err("UNSUPPORTED_CLIENT_REPORT_SCHEMA".into()); }
    let mut ids = HashSet::new();
    if report.results.iter().any(|r| r.id.is_empty() || !ids.insert(&r.id)) {
        return Err("DUPLICATE_OR_EMPTY_REQUIREMENT_ID".into());
    }
    Ok(report)
}
fn sha(v: &str) -> bool { v.len()==64 && v.bytes().all(|b|b.is_ascii_hexdigit()) }
fn matching(e: Option<&str>, a: Option<&str>) -> bool {
    e.zip(a).is_some_and(|(e,a)|sha(e)&&sha(a)&&e.eq_ignore_ascii_case(a))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        json!({"schemaVersion":"baradwatchu.audit.v1","completedAtUnixMs":1,"results":[{"id":"REQ-001","name":"Updates","priority":"HIGH","status":"PASS","summary":"ok","details":[],"completedAtUnixMs":1}]})
    }
    fn provenance(value: &mut Value) {
        value["results"][0]["provenance"]=json!({"toolId":"REQ-001","origin":"BUILTIN","expectedSha256":"a".repeat(64),"actualSha256":"a".repeat(64),"integrityStatus":"VERIFIED","integrityScope":"CHECK_FOLDER","isOverride":false});
    }
    #[test]
    fn legacy_report_is_readable_but_missing_evidence_is_unknown() {
        let value=fixture(); let r=parse(&value).unwrap();
        assert!(r.initiator.is_none());
        assert_eq!(inspect(&r,&[])["coherence"],"UNKNOWN");
    }
    #[test]
    fn rejects_unknown_schema_duplicate_ids_and_malformed_contract() {
        let mut v=fixture();v["schemaVersion"]=json!("future");assert!(parse(&v).is_err());
        v=fixture();let row=v["results"][0].clone();v["results"].as_array_mut().unwrap().push(row);assert!(parse(&v).is_err());
        v=fixture();v["results"][0]["status"]=json!("FAKE");assert!(parse(&v).is_err());
    }
    #[test]
    fn verified_claim_cannot_hide_a_hash_difference() {
        let mut v=fixture();provenance(&mut v);v["results"][0]["provenance"]["actualSha256"]=json!("b".repeat(64));
        let r=parse(&v).unwrap();let b=RequirementBaseline{id:"REQ-001".into(),name:"Updates".into(),expected_sha256:"b".repeat(64),enabled:true};
        let checked=inspect(&r,&[b]);assert_eq!(checked["coherence"],"INCONSISTENT");assert_eq!(checked["items"][0]["state"],"INCONSISTENT");
    }
    #[test]
    fn folder_gate_can_fail_with_a_matching_entrypoint_and_disabled_does_not_execute() {
        let mut v=fixture();provenance(&mut v);v["results"][0]["provenance"]["integrityStatus"]=json!("MISMATCH");v["results"][0]["status"]=json!("ERROR");
        assert_eq!(inspect(&parse(&v).unwrap(),&[])["coherence"],"COHERENT");
        v["results"][0]["status"]=json!("DISABLED");assert_eq!(inspect(&parse(&v).unwrap(),&[])["coherence"],"COHERENT");
        v["results"][0]["status"]=json!("PASS");assert_eq!(inspect(&parse(&v).unwrap(),&[])["coherence"],"INCONSISTENT");
    }
    #[test]
    fn per_file_and_installation_summary_are_checked() {
        let mut v=fixture();provenance(&mut v);
        v["installation"]=json!({"status":"VERIFIED","platform":"linux","manifestSha256":"c".repeat(64),"verifiedFiles":1,"files":[{"requirementId":"REQ-001","path":"catalog/checks/REQ-001/check.sh","expectedSha256":"a".repeat(64),"actualSha256":"b".repeat(64),"state":"VERIFIED"}]});
        let result=inspect(&parse(&v).unwrap(),&[]);assert_eq!(result["coherence"],"INCONSISTENT");assert!(result["issues"].as_array().unwrap().iter().any(|i|i["code"]=="FILE_STATE_HASH_CONTRADICTION"));
        v["installation"]["files"][0]["actualSha256"]=json!("a".repeat(64));assert_eq!(inspect(&parse(&v).unwrap(),&[])["coherence"],"COHERENT");
        v["installation"]["verifiedFiles"]=json!(0);assert_eq!(inspect(&parse(&v).unwrap(),&[])["coherence"],"INCONSISTENT");
    }
}
pub fn inspect(report: &AuditReport, baselines: &[RequirementBaseline]) -> Value {
    let mut issues=Vec::<Value>::new();
    let mut problem=|id:&str,code:&str|issues.push(json!({"id":id,"code":code}));
    if report.client.sha256.as_deref().is_some_and(|v|!sha(v)) { problem("CLIENT","INVALID_EXECUTABLE_SHA256"); }
    if let Some(installation)=&report.installation {
        if !sha(&installation.manifest_sha256) { problem("INSTALLATION","INVALID_MANIFEST_SHA256"); }
        let mut paths=HashSet::new();
        let mut verified=0;
        for file in &installation.files {
            if !paths.insert(&file.path) { problem(&file.requirement_id,"DUPLICATE_INSTALLATION_PATH"); }
            if file.path.starts_with('/') || file.path.split(['/', '\\']).any(|p|p=="..") { problem(&file.requirement_id,"UNSAFE_INSTALLATION_PATH"); }
            let expected=file.expected_sha256.as_deref();
            let actual=file.actual_sha256.as_deref();
            if expected.into_iter().chain(actual).any(|v|!sha(v)) { problem(&file.requirement_id,"INVALID_FILE_SHA256"); }
            let equal=matching(expected,actual);
            let coherent=match file.state {
                FileState::Verified=>{verified+=1;equal},
                FileState::Modified=>expected.is_some()&&actual.is_some()&&!equal,
                FileState::Missing|FileState::Unsafe=>actual.is_none(),
                FileState::Unexpected=>expected.is_none()&&actual.is_some(),
            };
            if !coherent { problem(&file.requirement_id,"FILE_STATE_HASH_CONTRADICTION"); }
        }
        let all_verified=verified==installation.files.len()&&verified>0;
        if installation.verified_files!=verified || (installation.status==IntegrityStatus::Verified)!=all_verified { problem("INSTALLATION","INSTALLATION_SUMMARY_CONTRADICTION"); }
    }
    for result in &report.results {
        let Some(p)=&result.provenance else {continue};
        if p.expected_sha256.iter().chain(p.actual_sha256.iter()).chain(p.builtin_expected_sha256.iter()).any(|v|!sha(v)) { problem(&result.id,"INVALID_TOOL_SHA256"); }
        if p.integrity_status==IntegrityStatus::Verified && !matching(p.expected_sha256.as_deref(),p.actual_sha256.as_deref()) { problem(&result.id,"VERIFIED_TOOL_HASH_CONTRADICTION"); }
        if !matches!(p.integrity_scope.as_str(),"CHECK_FOLDER"|"ENTRYPOINT_FILE_ONLY") { problem(&result.id,"UNKNOWN_INTEGRITY_SCOPE"); }
        // A failed folder gate may have a matching entrypoint hash: another file differs.
        if p.integrity_status==IntegrityStatus::Mismatch && !matches!(result.status,ResultStatus::Error|ResultStatus::Disabled|ResultStatus::NotApplicable) { problem(&result.id,"INTEGRITY_GATE_RESULT_CONTRADICTION"); }
        if p.integrity_scope=="CHECK_FOLDER" && p.integrity_status==IntegrityStatus::Verified && !matches!(result.status,ResultStatus::Disabled|ResultStatus::NotApplicable) {
            if let Some(installation)=&report.installation {
                let id=p.override_builtin_id.as_deref().unwrap_or(&result.id);
                let files:Vec<_>=installation.files.iter().filter(|f|f.requirement_id==id).collect();
                if files.is_empty() || files.iter().any(|f|f.state!=FileState::Verified) { problem(&result.id,"VERIFIED_FOLDER_CONTRADICTION"); }
            }
        }
    }
    let items:Vec<_>=baselines.iter().filter(|b|b.enabled).map(|b| {
        let result=report.results.iter().find(|r|r.id==b.id);
        let p=result.and_then(|r|r.provenance.as_ref());
        let actual=p.and_then(|p|p.actual_sha256.as_deref());
        let inconsistent=issues.iter().any(|i|i["id"]==b.id||i["id"]=="INSTALLATION");
        let state=if inconsistent{"INCONSISTENT"}else if result.is_none(){"MISSING"}else if actual.is_none(){"UNKNOWN"}else if !matching(Some(&b.expected_sha256),actual){"MISMATCH"}else if p.is_some_and(|p|p.integrity_status==IntegrityStatus::Verified){"MATCH"}else{"UNVERIFIED"};
        json!({"id":b.id,"name":b.name,"expectedSha256":b.expected_sha256,"reportedSha256":actual,"state":state,"scope":p.map(|p|&p.integrity_scope)})
    }).collect();
    json!({"source":"Client observations authenticated by mTLS; SHA coherence is not proof of execution or a report signature.","coherence":if !issues.is_empty(){"INCONSISTENT"}else if report.installation.is_none()&&report.results.iter().all(|r|r.provenance.is_none()){"UNKNOWN"}else{"COHERENT"},"issues":issues,"items":items,"installationEvidenceAvailable":report.installation.is_some(),"provenanceAvailable":report.results.iter().all(|r|r.provenance.is_some())})
}
