//! SQLite holds configuration, pairing and received report history; never OAuth tokens.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

pub type Result<T> = std::result::Result<T, String>;
pub const ISSUER: &str = "https://accounts.google.com";
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub fn random() -> Result<String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| "random source unavailable")?;
    Ok(hex(&b))
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
pub fn fingerprint(key: &[u8; 32]) -> String {
    format!("SHA256:{}", hex(&Sha256::digest(key)))
}
pub fn derived_id(key: &[u8; 32], server: bool) -> String {
    let (prefix, domain) = if server {
        ("SRV", "baradwatchu.server-id.v1\0")
    } else {
        ("BWU", "baradwatchu.device-id.v1\0")
    };
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(key);
    let h = hex(&hash.finalize()[..8]).to_uppercase();
    format!(
        "{prefix}-{}-{}-{}-{}",
        &h[..4],
        &h[4..8],
        &h[8..12],
        &h[12..]
    )
}
pub fn label(value: &str) -> bool {
    !value.trim().is_empty()
        && value.chars().count() <= 128
        && !value.chars().any(|c| {
            c.is_control()
                || matches!(c,'\u{200e}'|'\u{200f}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
        })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicIdentity {
    pub schema_version: String,
    pub role: String,
    pub algorithm: String,
    pub public_key: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub created_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_sha256: Option<String>,
}
impl PublicIdentity {
    pub fn key(&self, role: &str) -> Result<[u8; 32]> {
        if self.schema_version != "baradwatchu.public-identity.v1"
            || self.algorithm != "Ed25519"
            || self.role != role
        {
            return Err("invalid identity schema, role or algorithm".into());
        }
        let key: [u8; 32] = STANDARD
            .decode(&self.public_key)
            .map_err(|_| "invalid key")?
            .try_into()
            .map_err(|_| "invalid key length")?;
        let vk = VerifyingKey::from_bytes(&key).map_err(|_| "invalid Ed25519 key")?;
        if vk.is_weak() || STANDARD.encode(key) != self.public_key {
            return Err("invalid Ed25519 key".into());
        }
        if self
            .id
            .as_ref()
            .is_some_and(|id| *id != derived_id(&key, role == "server"))
            || self
                .fingerprint
                .as_ref()
                .is_some_and(|fp| *fp != fingerprint(&key))
        {
            return Err("identity fingerprint or ID mismatch".into());
        }
        if self
            .executable_sha256
            .as_deref()
            .is_some_and(|sha| !valid_sha256(sha))
        {
            return Err("invalid Client executable SHA-256".into());
        }
        Ok(key)
    }
}
pub fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedClient {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequirementBaseline {
    pub id: String,
    pub name: String,
    pub expected_sha256: String,
    pub enabled: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Operator {
    pub issuer: String,
    pub sub: String,
    pub name: String,
    pub email: String,
}
pub struct Store(Mutex<Connection>);
impl Store {
    pub fn open(dir: &Path) -> Result<Self> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| e.to_string())?;
        let meta = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err("Server data directory must be owner-only (0700) and not a symlink".into());
        }
        let path = dir.join("server.sqlite3");
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| e.to_string())?;
        let m = f.metadata().map_err(|e| e.to_string())?;
        if !m.is_file()
            || m.uid() != unsafe { libc::geteuid() }
            || m.permissions().mode() & 0o077 != 0
        {
            return Err("Server database must be owner-only (0600)".into());
        }
        Self::init(Connection::open(path).map_err(|e| e.to_string())?)
    }
    fn init(c: Connection) -> Result<Self> {
        c.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        c.execute_batch("PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1), seed BLOB NOT NULL, name TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, public_key TEXT UNIQUE NOT NULL, fingerprint TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS administrators (issuer TEXT NOT NULL, sub TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '', PRIMARY KEY(issuer,sub));
CREATE TABLE IF NOT EXISTS received_reports (operator TEXT NOT NULL, request_id TEXT NOT NULL, client_id TEXT NOT NULL, client_name TEXT NOT NULL, fingerprint TEXT NOT NULL, completed INTEGER NOT NULL, report TEXT NOT NULL, PRIMARY KEY(operator,request_id));
CREATE TABLE IF NOT EXISTS expected_manifest (singleton INTEGER PRIMARY KEY CHECK(singleton=1), content TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS manifest_sha_override (singleton INTEGER PRIMARY KEY CHECK(singleton=1), sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS client_executable_sha (client_id TEXT PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE, imported_sha256 TEXT, override_sha256 TEXT);
CREATE TABLE IF NOT EXISTS requirement_definitions (id TEXT PRIMARY KEY, configuration TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS requirement_baselines (id TEXT PRIMARY KEY, name TEXT NOT NULL, expected_sha256 TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS server_custom_checks (id TEXT PRIMARY KEY, package TEXT NOT NULL);").map_err(|e|e.to_string())?;
        let has_endpoint = {
            let mut statement = c
                .prepare("PRAGMA table_info(clients)")
                .map_err(|e| e.to_string())?;
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|e| e.to_string())?;
            columns
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?
                .iter()
                .any(|column| column == "endpoint")
        };
        if has_endpoint {
            c.execute("ALTER TABLE clients DROP COLUMN endpoint", [])
                .map_err(|e| e.to_string())?;
        }
        Ok(Self(Mutex::new(c)))
    }
    #[cfg(test)]
    pub fn memory() -> Self {
        Self::init(Connection::open_in_memory().unwrap()).unwrap()
    }
    pub fn generate(&self, name: &str) -> Result<PublicIdentity> {
        if !label(name) {
            return Err("invalid Server name".into());
        }
        let mut seed = [0; 32];
        getrandom::fill(&mut seed).map_err(|_| "random source unavailable")?;
        self.0
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO identity VALUES(1,?1,?2,?3)",
                params![seed.as_slice(), name, now_ms()],
            )
            .map_err(|_| "identity already exists; explicit manual rotation required")?;
        self.identity()?.ok_or("identity unavailable".into())
    }
    pub fn signing_key(&self) -> Result<SigningKey> {
        let seed: Vec<u8> = self
            .0
            .lock()
            .unwrap()
            .query_row("SELECT seed FROM identity WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(|_| "generate the Server identity explicitly first")?;
        Ok(SigningKey::from_bytes(
            &seed.try_into().map_err(|_| "damaged identity")?,
        ))
    }
    pub fn expected_manifest(&self) -> Result<Option<String>> {
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT content FROM expected_manifest WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())
    }
    pub fn save_expected_manifest(&self, text: &str) -> Result<()> {
        crate::manifest::parse(text)?;
        self.0.lock().unwrap().execute("INSERT INTO expected_manifest(singleton,content) VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET content=excluded.content",[text]).map_err(|e|e.to_string())?;
        Ok(())
    }
    pub fn remove_expected_manifest(&self) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM expected_manifest", [])
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn manifest_sha_override(&self) -> Result<Option<String>> {
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT sha256 FROM manifest_sha_override WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())
    }
    pub fn set_manifest_sha_override(&self, sha: Option<&str>) -> Result<()> {
        if let Some(value) = sha {
            if !valid_sha256(value) {
                return Err("invalid manifest SHA-256".into());
            }
            self.0.lock().unwrap().execute("INSERT INTO manifest_sha_override(singleton,sha256) VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET sha256=excluded.sha256",[value.to_ascii_lowercase()]).map_err(|e|e.to_string())?;
        } else {
            self.0
                .lock()
                .unwrap()
                .execute("DELETE FROM manifest_sha_override", [])
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
    pub fn client_executable_sha(&self, id: &str) -> Result<(Option<String>, Option<String>)> {
        self.0.lock().unwrap().query_row("SELECT imported_sha256,override_sha256 FROM client_executable_sha WHERE client_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?))).optional().map(|row|row.unwrap_or((None,None))).map_err(|e|e.to_string())
    }
    pub fn set_client_executable_sha_override(&self, id: &str, sha: Option<&str>) -> Result<()> {
        if let Some(value) = sha {
            if !valid_sha256(value) {
                return Err("invalid Client executable SHA-256".into());
            }
        }
        let db = self.0.lock().unwrap();
        let exists: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM clients WHERE id=?1)",
                [id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !exists {
            return Err("CLIENT_NOT_REGISTERED".into());
        }
        db.execute("INSERT INTO client_executable_sha(client_id,override_sha256) VALUES(?1,?2) ON CONFLICT(client_id) DO UPDATE SET override_sha256=excluded.override_sha256",params![id,sha.map(str::to_ascii_lowercase)]).map_err(|e|e.to_string())?;
        Ok(())
    }
    pub fn requirement_definitions(
        &self,
    ) -> Result<Vec<crate::requirement_config::CheckConfiguration>> {
        let c = self.0.lock().unwrap();
        let mut q = c
            .prepare("SELECT configuration FROM requirement_definitions ORDER BY id")
            .map_err(|e| e.to_string())?;
        let rows = q
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        rows.map(|row| {
            serde_json::from_str(&row.map_err(|e| e.to_string())?).map_err(|e| e.to_string())
        })
        .collect()
    }
    pub fn save_requirement_definition(
        &self,
        config: &crate::requirement_config::CheckConfiguration,
    ) -> Result<()> {
        config.validate()?;
        let text = serde_json::to_string(config).map_err(|e| e.to_string())?;
        self.0.lock().unwrap().execute("INSERT INTO requirement_definitions(id,configuration) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET configuration=excluded.configuration",params![config.id,text]).map_err(|e|e.to_string())?;
        Ok(())
    }
    pub fn remove_requirement_definition(&self, id: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM requirement_definitions WHERE id=?1", [id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn server_custom_checks(&self) -> Result<Vec<crate::custom_checks::CustomCheck>> {
        let c = self.0.lock().unwrap();
        let mut q = c
            .prepare("SELECT package FROM server_custom_checks ORDER BY id")
            .map_err(|e| e.to_string())?;
        let rows = q
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        rows.map(|row| {
            serde_json::from_str(&row.map_err(|e| e.to_string())?).map_err(|e| e.to_string())
        })
        .collect()
    }
    pub fn server_custom_check(&self, id: &str) -> Result<crate::custom_checks::CustomCheck> {
        let text = self
            .0
            .lock()
            .unwrap()
            .query_row(
                "SELECT package FROM server_custom_checks WHERE id=?1",
                [id],
                |r| r.get::<_, String>(0),
            )
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&text).map_err(|e| e.to_string())
    }
    pub fn save_server_custom_check(&self, item: &crate::custom_checks::CustomCheck) -> Result<()> {
        item.validate()?;
        let text = serde_json::to_string(item).map_err(|e| e.to_string())?;
        self.0.lock().unwrap().execute(
            "INSERT INTO server_custom_checks(id,package) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET package=excluded.package",
            params![item.id, text],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn remove_server_custom_check(&self, id: &str) -> Result<()> {
        let changed = self
            .0
            .lock()
            .unwrap()
            .execute("DELETE FROM server_custom_checks WHERE id=?1", [id])
            .map_err(|e| e.to_string())?;
        if changed == 0 {
            return Err("custom check not found".into());
        }
        Ok(())
    }
    pub fn requirement_baselines(&self) -> Result<Vec<RequirementBaseline>> {
        let c = self.0.lock().unwrap();
        let mut q = c
            .prepare(
                "SELECT id,name,expected_sha256,enabled FROM requirement_baselines ORDER BY id",
            )
            .map_err(|e| e.to_string())?;
        let rows = q
            .query_map([], |r| {
                Ok(RequirementBaseline {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    expected_sha256: r.get(2)?,
                    enabled: r.get::<_, i64>(3)? != 0,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
    pub fn save_requirement_baseline(&self, item: &RequirementBaseline) -> Result<()> {
        if item.id.is_empty()
            || item.id.len() > 128
            || !item
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || item.name.trim().is_empty()
            || item.name.chars().count() > 256
            || item.expected_sha256.len() != 64
            || !item.expected_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(
                "invalid requirement baseline; expected ID, name and SHA-256 hex digest".into(),
            );
        }
        self.0.lock().unwrap().execute("INSERT INTO requirement_baselines(id,name,expected_sha256,enabled) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET name=excluded.name,expected_sha256=excluded.expected_sha256,enabled=excluded.enabled", params![item.id,item.name,item.expected_sha256.to_ascii_lowercase(),item.enabled as i64]).map_err(|e|e.to_string())?;
        Ok(())
    }
    pub fn remove_requirement_baseline(&self, id: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM requirement_baselines WHERE id=?1", [id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn identity(&self) -> Result<Option<PublicIdentity>> {
        let row: Option<(Vec<u8>, String, u64)> = self
            .0
            .lock()
            .unwrap()
            .query_row(
                "SELECT seed,name,created FROM identity WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        row.map(|(seed, name, created)| {
            let seed: [u8; 32] = seed.try_into().map_err(|_| "damaged identity")?;
            let key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            Ok(PublicIdentity {
                schema_version: "baradwatchu.public-identity.v1".into(),
                role: "server".into(),
                algorithm: "Ed25519".into(),
                public_key: STANDARD.encode(key),
                id: Some(derived_id(&key, true)),
                name: Some(name),
                fingerprint: Some(fingerprint(&key)),
                created_at_unix_ms: Some(created),
                executable_sha256: None,
            })
        })
        .transpose()
    }
    pub fn import(
        &self,
        identity: PublicIdentity,
        name: &str,
        confirmed: &str,
    ) -> Result<TrustedClient> {
        let key = identity.key("client")?;
        if confirmed != fingerprint(&key) {
            return Err("confirm the independently verified fingerprint".into());
        }
        if !label(name) {
            return Err("provide a Client name".into());
        }
        let own = self.signing_key()?.verifying_key().to_bytes();
        if own == key {
            return Err("cannot trust own identity as a Client".into());
        }
        let c = TrustedClient {
            id: derived_id(&key, false),
            name: name.into(),
            public_key: STANDARD.encode(key),
            fingerprint: fingerprint(&key),
        };
        let mut db = self.0.lock().unwrap();
        let tx = db.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO clients(id,name,public_key,fingerprint) VALUES(?1,?2,?3,?4)",
            params![c.id, c.name, c.public_key, c.fingerprint],
        )
        .map_err(|_| "Client already registered")?;
        if let Some(sha) = identity.executable_sha256 {
            tx.execute(
                "INSERT INTO client_executable_sha(client_id,imported_sha256) VALUES(?1,?2)",
                params![c.id, sha.to_ascii_lowercase()],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(c)
    }
    pub fn clients(&self) -> Result<Vec<TrustedClient>> {
        let db = self.0.lock().unwrap();
        let mut s = db
            .prepare("SELECT id,name,public_key,fingerprint FROM clients ORDER BY name")
            .map_err(|e| e.to_string())?;
        let rows = s
            .query_map([], |r| {
                Ok(TrustedClient {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    public_key: r.get(2)?,
                    fingerprint: r.get(3)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
    pub fn remove_client(&self, id: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM clients WHERE id=?1", [id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn allow(&self, sub: &str) -> Result<()> {
        if sub.is_empty() || sub.len() > 255 || sub.chars().any(char::is_control) {
            return Err("invalid Google subject".into());
        }
        self.0
            .lock()
            .unwrap()
            .execute(
                "INSERT OR IGNORE INTO administrators(issuer,sub) VALUES(?1,?2)",
                params![ISSUER, sub],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn revoke(&self, sub: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM administrators WHERE issuer=?1 AND sub=?2",
                params![ISSUER, sub],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn authorized(&self, op: &Operator) -> bool {
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT 1 FROM administrators WHERE issuer=?1 AND sub=?2",
                params![op.issuer, op.sub],
                |_| Ok(()),
            )
            .optional()
            .ok()
            .flatten()
            .is_some()
    }
    pub fn update_operator(&self, op: &Operator) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute(
                "UPDATE administrators SET name=?3,email=?4 WHERE issuer=?1 AND sub=?2",
                params![op.issuer, op.sub, op.name, op.email],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
use std::os::unix::fs::DirBuilderExt;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_and_allowlist_survive_reopen_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("bwu-server-store-{}", random().unwrap()));
        let db = Store::open(&dir).unwrap();
        let identity = db.generate("Server").unwrap();
        db.allow("operator").unwrap();
        drop(db);
        let db = Store::open(&dir).unwrap();
        assert_eq!(
            db.identity().unwrap().unwrap().public_key,
            identity.public_key
        );
        assert!(db.authorized(&Operator {
            issuer: ISSUER.into(),
            sub: "operator".into(),
            name: String::new(),
            email: String::new()
        }));
        drop(db);
        std::fs::set_permissions(
            dir.join("server.sqlite3"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(Store::open(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn identity_is_explicit_stable_and_not_regenerated() {
        let s = Store::memory();
        assert!(s.identity().unwrap().is_none());
        let p = s.generate("Test Server").unwrap();
        assert_eq!(
            p.key("server").unwrap(),
            s.signing_key().unwrap().verifying_key().to_bytes()
        );
        assert!(s.generate("Another").is_err());
        assert_eq!(p.public_key, s.identity().unwrap().unwrap().public_key);
    }
    #[test]
    fn authorization_is_issuer_subject_not_name_or_email() {
        let s = Store::memory();
        let mut op = Operator {
            issuer: ISSUER.into(),
            sub: "1".into(),
            name: "Mario".into(),
            email: "m@example.com".into(),
        };
        assert!(!s.authorized(&op));
        s.allow("1").unwrap();
        s.allow("2").unwrap();
        assert!(s.authorized(&op));
        op.sub = "2".into();
        assert!(s.authorized(&op));
        op.issuer = "https://evil.example".into();
        assert!(!s.authorized(&op));
        op.issuer = ISSUER.into();
        s.revoke("2").unwrap();
        assert!(!s.authorized(&op));
    }
    #[test]
    fn manual_trust_requires_matching_fingerprint_and_role() {
        let s = Store::memory();
        s.generate("Server").unwrap();
        let k = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        let mut p = PublicIdentity {
            schema_version: "baradwatchu.public-identity.v1".into(),
            role: "client".into(),
            algorithm: "Ed25519".into(),
            public_key: STANDARD.encode(k),
            id: None,
            name: None,
            fingerprint: None,
            created_at_unix_ms: None,
            executable_sha256: None,
        };
        assert!(s.import(p.clone(), "PC", "wrong").is_err());
        s.import(p.clone(), "PC", &fingerprint(&k)).unwrap();
        assert_eq!(s.clients().unwrap().len(), 1);
        p.role = "server".into();
        assert!(s.import(p, "PC", &fingerprint(&k)).is_err());
    }
}

impl Store {
    /// Preserve the received JSON value, including unknown extension fields. Never synthesize an audit.
    pub fn remember_report(
        &self,
        operator: &str,
        request_id: &str,
        client: &TrustedClient,
        report: &serde_json::Value,
    ) -> Result<()> {
        let parsed = crate::report_integrity::parse(report)?;
        let text = serde_json::to_string(report).map_err(|e| e.to_string())?;
        let c = self.0.lock().unwrap();
        let previous:Option<(String,String,String)>=c.query_row("SELECT client_id,fingerprint,report FROM received_reports WHERE operator=?1 AND request_id=?2",params![operator,request_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(|e|e.to_string())?;
        if let Some((id, fingerprint, old)) = previous {
            if id != client.id || fingerprint != client.fingerprint || old != text {
                return Err("RECEIVED_REPORT_CHANGED".into());
            }
            return Ok(());
        }
        c.execute("INSERT INTO received_reports(operator,request_id,client_id,client_name,fingerprint,completed,report) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![operator,request_id,client.id,client.name,client.fingerprint,parsed.completed_at_unix_ms,text]).map_err(|e|e.to_string())?;
        Ok(())
    }
    pub fn history(&self, operator: &str) -> Result<Vec<serde_json::Value>> {
        let c = self.0.lock().unwrap();
        let mut q=c.prepare("SELECT request_id,client_id,client_name,fingerprint,completed,length(CAST(report AS BLOB)) FROM received_reports WHERE operator=?1 ORDER BY completed DESC,request_id").map_err(|e|e.to_string())?;
        let rows=q.query_map([operator],|r|Ok(serde_json::json!({"id":r.get::<_,String>(0)?,"clientId":r.get::<_,String>(1)?,"clientName":r.get::<_,String>(2)?,"fingerprint":r.get::<_,String>(3)?,"completedAtUnixMs":r.get::<_,u64>(4)?,"files":1,"bytes":r.get::<_,u64>(5)?}))).map_err(|e|e.to_string())?;
        rows.collect::<std::result::Result<_, _>>()
            .map_err(|e| e.to_string())
    }
    pub fn history_report(&self, operator: &str, id: &str) -> Result<Option<serde_json::Value>> {
        let text: Option<String> = self
            .0
            .lock()
            .unwrap()
            .query_row(
                "SELECT report FROM received_reports WHERE operator=?1 AND request_id=?2",
                params![operator, id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        text.map(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
            .transpose()
    }
    pub fn history_client_id(&self, operator: &str, id: &str) -> Result<Option<String>> {
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT client_id FROM received_reports WHERE operator=?1 AND request_id=?2",
                params![operator, id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())
    }
    pub fn history_usage(&self, operator: &str) -> Result<serde_json::Value> {
        self.0.lock().unwrap().query_row("SELECT count(*),coalesce(sum(length(CAST(report AS BLOB))),0) FROM received_reports WHERE operator=?1",[operator],|r|Ok(serde_json::json!({"audits":r.get::<_,u64>(0)?,"files":r.get::<_,u64>(0)?,"bytes":r.get::<_,u64>(1)?}))).map_err(|e|e.to_string())
    }
    pub fn remove_history(&self, operator: &str, id: Option<&str>) -> Result<serde_json::Value> {
        let mut c = self.0.lock().unwrap();
        let tx = c.transaction().map_err(|e| e.to_string())?;
        let (count,bytes):(u64,u64)=tx.query_row("SELECT count(*),coalesce(sum(length(CAST(report AS BLOB))),0) FROM received_reports WHERE operator=?1 AND (?2 IS NULL OR request_id=?2)",params![operator,id],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|e|e.to_string())?;
        tx.execute(
            "DELETE FROM received_reports WHERE operator=?1 AND (?2 IS NULL OR request_id=?2)",
            params![operator, id],
        )
        .map_err(|e| e.to_string())?;
        let usage=tx.query_row("SELECT count(*),coalesce(sum(length(CAST(report AS BLOB))),0) FROM received_reports WHERE operator=?1",[operator],|r|Ok(serde_json::json!({"audits":r.get::<_,u64>(0)?,"files":r.get::<_,u64>(0)?,"bytes":r.get::<_,u64>(1)?}))).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(
            serde_json::json!({"removedAudits":count,"removedFiles":count,"freedBytes":bytes,"usage":usage}),
        )
    }
}

#[cfg(test)]
mod history_tests {
    use super::*;
    use serde_json::json;
    fn client() -> TrustedClient {
        TrustedClient {
            id: "BWU-test".into(),
            name: "Workstation".into(),
            public_key: "key".into(),
            fingerprint: "SHA256:test".into(),
        }
    }
    fn report() -> serde_json::Value {
        json!({"schemaVersion":"baradwatchu.audit.v1","completedAtUnixMs":123,"results":[],"futureExtension":{"original":true}})
    }
    #[test]
    fn history_is_scoped_to_operator_and_preserves_received_json() {
        let store = Store::memory();
        let value = report();
        store
            .remember_report("alice", "request", &client(), &value)
            .unwrap();
        assert_eq!(
            store.history_report("alice", "request").unwrap(),
            Some(value.clone())
        );
        assert!(store.history_report("bob", "request").unwrap().is_none());
        assert!(store.history("bob").unwrap().is_empty());
        assert_eq!(
            store.remove_history("bob", Some("request")).unwrap()["removedAudits"],
            0
        );
        assert_eq!(
            store.history("alice").unwrap()[0]["clientName"],
            "Workstation"
        );
        assert_eq!(store.history_usage("alice").unwrap()["audits"], 1);
        let bytes = serde_json::to_vec(&value).unwrap().len();
        assert_eq!(store.history_usage("alice").unwrap()["bytes"], bytes);
    }
    #[test]
    fn repeated_fetch_is_idempotent_but_changed_report_is_rejected() {
        let store = Store::memory();
        let value = report();
        store
            .remember_report("alice", "request", &client(), &value)
            .unwrap();
        store
            .remember_report("alice", "request", &client(), &value)
            .unwrap();
        assert_eq!(store.history("alice").unwrap().len(), 1);
        let mut changed = value.clone();
        changed["completedAtUnixMs"] = json!(124);
        assert!(store
            .remember_report("alice", "request", &client(), &changed)
            .is_err());
        assert_eq!(
            store.history_report("alice", "request").unwrap(),
            Some(value)
        );
    }
    #[test]
    fn delete_and_clear_remove_only_requested_operators_reports() {
        let store = Store::memory();
        let value = report();
        for (operator, id) in [("alice", "one"), ("alice", "two"), ("bob", "one")] {
            store
                .remember_report(operator, id, &client(), &value)
                .unwrap();
        }
        let removed = store.remove_history("alice", Some("one")).unwrap();
        assert_eq!(removed["removedAudits"], 1);
        assert_eq!(removed["usage"]["audits"], 1);
        let removed = store.remove_history("alice", None).unwrap();
        assert_eq!(removed["removedAudits"], 1);
        assert_eq!(removed["usage"]["bytes"], 0);
        assert_eq!(store.history("bob").unwrap().len(), 1);
    }
    #[test]
    fn report_history_survives_database_reopen_without_request_records() {
        let directory = std::env::temp_dir().join(format!("bwu-history-{}", random().unwrap()));
        let value = report();
        {
            let store = Store::open(&directory).unwrap();
            store
                .remember_report("alice", "request", &client(), &value)
                .unwrap();
        }
        {
            let store = Store::open(&directory).unwrap();
            assert_eq!(
                store.history_report("alice", "request").unwrap(),
                Some(value)
            );
            assert!(store.identity().unwrap().is_none());
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
