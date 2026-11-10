//! SQLite holds configuration and pairing, never audit reports or OAuth tokens.
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
        Ok(key)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedClient {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub public_key: String,
    pub fingerprint: String,
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
CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, endpoint TEXT NOT NULL, public_key TEXT UNIQUE NOT NULL, fingerprint TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS administrators (issuer TEXT NOT NULL, sub TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '', PRIMARY KEY(issuer,sub));").map_err(|e|e.to_string())?;
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
            })
        })
        .transpose()
    }
    pub fn import(
        &self,
        identity: PublicIdentity,
        name: &str,
        endpoint: &str,
        confirmed: &str,
    ) -> Result<TrustedClient> {
        let key = identity.key("client")?;
        if confirmed != fingerprint(&key) {
            return Err("confirm the independently verified fingerprint".into());
        }
        if !label(name) || endpoint.parse::<std::net::SocketAddr>().is_err() {
            return Err("provide a name and an explicit IP:port endpoint".into());
        }
        let own = self.signing_key()?.verifying_key().to_bytes();
        if own == key {
            return Err("cannot trust own identity as a Client".into());
        }
        let c = TrustedClient {
            id: derived_id(&key, false),
            name: name.into(),
            endpoint: endpoint.into(),
            public_key: STANDARD.encode(key),
            fingerprint: fingerprint(&key),
        };
        self.0
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO clients VALUES(?1,?2,?3,?4,?5)",
                params![c.id, c.name, c.endpoint, c.public_key, c.fingerprint],
            )
            .map_err(|_| "Client already registered")?;
        Ok(c)
    }
    pub fn clients(&self) -> Result<Vec<TrustedClient>> {
        let db = self.0.lock().unwrap();
        let mut s = db
            .prepare("SELECT id,name,endpoint,public_key,fingerprint FROM clients ORDER BY name")
            .map_err(|e| e.to_string())?;
        let rows = s
            .query_map([], |r| {
                Ok(TrustedClient {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    endpoint: r.get(2)?,
                    public_key: r.get(3)?,
                    fingerprint: r.get(4)?,
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
        };
        assert!(s
            .import(p.clone(), "PC", "127.0.0.1:7443", "wrong")
            .is_err());
        s.import(p.clone(), "PC", "127.0.0.1:7443", &fingerprint(&k))
            .unwrap();
        assert_eq!(s.clients().unwrap().len(), 1);
        p.role = "server".into();
        assert!(s
            .import(p, "PC", "127.0.0.1:7443", &fingerprint(&k))
            .is_err());
    }
}
