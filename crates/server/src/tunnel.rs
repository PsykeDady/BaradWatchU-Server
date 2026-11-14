//! Outbound Client connections. The dashboard never accepts network authentication here.
//!
//! The Server sends requests on the tunnel; a Client may send one kind of request of its own:
//! `POST /v1/change-reports` (Barad Policy periodic audit whose security state changed). It is
//! stored and acknowledged, never answered with a command.
use crate::{http::App, storage::TrustedClient, tls};
use base64::{engine::general_purpose::STANDARD, Engine};
use rustls::{
    pki_types::{CertificateDer, UnixTime},
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        ClientHello, ResolvesServerCert,
    },
    sign::CertifiedKey,
    DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

const MAX_FRAME: usize = 9 * 1024 * 1024;
const PROTOCOL: &str = "baradwatchu.tunnel.v1";
const CHANGE_REPORT_SCHEMA: &str = "baradwatchu.change-report.v1";
const CHANGE_REPORT_ACK_SCHEMA: &str = "baradwatchu.change-report-ack.v1";
pub const CHANGE_REPORT_PATH: &str = "/v1/change-reports";
/// Announced in the tunnel acknowledgement: Clients send change reports only when present.
const CHANGE_REPORT_FEATURE: &str = "CHANGE_REPORTS";

pub struct Reply {
    pub code: u16,
    pub body: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Hello {
    schema_version: String,
    device_id: String,
    name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestFrame<'a> {
    schema_version: &'static str,
    sequence: u64,
    method: &'a str,
    path: &'a str,
    body: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResponseFrame {
    schema_version: String,
    sequence: u64,
    code: u16,
    body: Value,
}

type Stream = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

struct Session {
    stream: Mutex<Stream>,
    next: AtomicU64,
    reported_name: String,
    client_id: String,
    /// Weak: the registry inside `App` holds the sessions.
    app: std::sync::Weak<App>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClientRequestFrame {
    schema_version: String,
    sequence: u64,
    method: String,
    path: String,
    body: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChangeReport {
    schema_version: String,
    report_id: String,
    device_id: String,
    /// The Client's normalized state digest (informative; the Server keeps the report).
    #[allow(dead_code)]
    state_sha256: String,
    report: Value,
}

fn valid_report_id(id: &str) -> bool {
    (8..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Stores a Client's automatic change report for every administrator (`storage::CLIENT_REPORTS`).
pub fn receive_change_report(app: &App, client_id: &str, body: Option<Value>) -> Reply {
    let error = |code: u16, error: &str| Reply {
        code,
        body: serde_json::json!({"schemaVersion": CHANGE_REPORT_ACK_SCHEMA, "error": error}),
    };
    let Some(change) = body.and_then(|body| serde_json::from_value::<ChangeReport>(body).ok())
    else {
        return error(400, "INVALID_CHANGE_REPORT");
    };
    if change.schema_version != CHANGE_REPORT_SCHEMA
        || !valid_report_id(&change.report_id)
        || change.device_id != client_id
        || change.report["initiator"]["origin"] != "SCHEDULED"
    {
        return error(400, "INVALID_CHANGE_REPORT");
    }
    if crate::report_integrity::parse(&change.report).is_err() {
        return error(400, "INVALID_CHANGE_REPORT");
    }
    let client = match app.store.clients() {
        Ok(clients) => clients.into_iter().find(|client| client.id == client_id),
        Err(_) => return error(503, "STORAGE_UNAVAILABLE"),
    };
    let Some(client) = client else {
        return error(403, "CLIENT_NOT_TRUSTED");
    };
    match app.store.remember_report(
        crate::storage::CLIENT_REPORTS,
        &change.report_id,
        &client,
        &change.report,
    ) {
        Ok(()) => Reply {
            code: 200,
            body: serde_json::json!({"schemaVersion": CHANGE_REPORT_ACK_SCHEMA, "reportId": change.report_id, "stored": true}),
        },
        Err(reason) if reason == "RECEIVED_REPORT_CHANGED" => error(409, "REPORT_ID_REUSED"),
        Err(_) => error(503, "STORAGE_UNAVAILABLE"),
    }
}

#[derive(Default)]
pub struct Registry {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
}

impl Registry {
    pub fn connected(&self, id: &str) -> bool {
        self.sessions.lock().unwrap().contains_key(id)
    }
    pub fn reported_name(&self, id: &str) -> Option<String> {
        self.sessions
            .lock()
            .unwrap()
            .get(id)
            .map(|session| session.reported_name.clone())
    }
    pub fn connected_ids(&self) -> Vec<String> {
        self.sessions.lock().unwrap().keys().cloned().collect()
    }
    fn remove_if_same(&self, id: &str, session: &Arc<Session>) {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions
            .get(id)
            .is_some_and(|current| Arc::ptr_eq(current, session))
        {
            sessions.remove(id);
        }
    }
    pub fn disconnect(&self, id: &str) {
        self.sessions.lock().unwrap().remove(id);
    }
    pub fn request(
        &self,
        client: &TrustedClient,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Reply, String> {
        let session = self
            .sessions
            .lock()
            .unwrap()
            .get(&client.id)
            .cloned()
            .ok_or("CLIENT_NOT_CONNECTED")?;
        let result = session.exchange(method, path, body);
        if result.is_err() {
            self.remove_if_same(&client.id, &session);
        }
        result
    }
}

pub async fn request(
    registry: Arc<Registry>,
    client: TrustedClient,
    method: &'static str,
    path: String,
    body: Option<Value>,
) -> Result<Reply, String> {
    tokio::task::spawn_blocking(move || registry.request(&client, method, &path, body))
        .await
        .map_err(|_| "tunnel worker failed".to_owned())?
}

impl Session {
    fn exchange(&self, method: &str, path: &str, body: Option<Value>) -> Result<Reply, String> {
        let mut stream = self.stream.lock().unwrap();
        let timeout = if path == "/v1/ping" {
            5
        } else if method == "POST" {
            25
        } else {
            15
        };
        stream
            .sock
            .set_read_timeout(Some(Duration::from_secs(timeout)))
            .map_err(|e| e.to_string())?;
        let sequence = self.next.fetch_add(1, Ordering::Relaxed);
        write_frame(
            &mut *stream,
            &RequestFrame {
                schema_version: PROTOCOL,
                sequence,
                method,
                path,
                body,
            },
        )?;
        // A Client request may arrive before our reply: answer it, then keep reading.
        let reply = read_reply(&mut *stream, |request| {
            match (request.method.as_str(), request.path.as_str()) {
                ("POST", CHANGE_REPORT_PATH) => match self.app.upgrade() {
                    Some(app) => receive_change_report(&app, &self.client_id, request.body),
                    None => Reply {
                        code: 503,
                        body: serde_json::json!({"schemaVersion": PROTOCOL, "error": "SERVER_STOPPING"}),
                    },
                },
                _ => Reply {
                    code: 404,
                    body: serde_json::json!({"schemaVersion": PROTOCOL, "error": "NOT_FOUND"}),
                },
            }
        })?;
        if reply.schema_version != PROTOCOL
            || reply.sequence != sequence
            || !(100..600).contains(&reply.code)
        {
            return Err("invalid Client tunnel response".into());
        }
        Ok(Reply {
            code: reply.code,
            body: reply.body,
        })
    }
}

/// Reads frames until the reply to our request, answering the Client's own requests on the way.
fn read_reply<S: Read + Write>(
    stream: &mut S,
    mut handle: impl FnMut(ClientRequestFrame) -> Reply,
) -> Result<ResponseFrame, String> {
    loop {
        let frame: Value = read_frame(stream)?;
        if frame.get("method").is_none() {
            return serde_json::from_value(frame)
                .map_err(|_| "invalid Client tunnel response".into());
        }
        let request: ClientRequestFrame = serde_json::from_value(frame)
            .map_err(|_| "invalid Client tunnel request".to_owned())?;
        if request.schema_version != PROTOCOL {
            return Err("invalid Client tunnel request".into());
        }
        let sequence = request.sequence;
        let answer = handle(request);
        write_frame(
            stream,
            &serde_json::json!({"schemaVersion": PROTOCOL, "sequence": sequence, "code": answer.code, "body": answer.body}),
        )?;
    }
}

fn write_frame<T: Serialize>(stream: &mut impl Write, frame: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(frame).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_FRAME {
        return Err("tunnel frame too large".into());
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(&bytes))
        .and_then(|_| stream.flush())
        .map_err(|e| e.to_string())
}

fn read_frame<T: DeserializeOwned>(stream: &mut impl Read) -> Result<T, String> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).map_err(|e| e.to_string())?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err("invalid tunnel frame".into());
    }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|_| "invalid tunnel JSON".into())
}

struct Verifier(Arc<App>);
impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientTunnelVerifier")
    }
}

#[derive(Debug)]
struct Resolver(Arc<CertifiedKey>);
impl ResolvesServerCert for Resolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for Verifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        let key = tls::key_from_spki(cert.as_ref());
        let trusted = key.is_some_and(|key| {
            self.0.store.clients().is_ok_and(|clients| {
                clients.iter().any(|client| {
                    STANDARD
                        .decode(&client.public_key)
                        .is_ok_and(|stored| stored == key)
                })
            })
        });
        if !intermediates.is_empty() || !trusted {
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 is not supported".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        tls::verify_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn accept(app: Arc<App>, tcp: TcpStream) -> Result<(), String> {
    tcp.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| e.to_string())?;
    let key = app.store.signing_key()?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(tls::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(Arc::new(Verifier(app.clone())))
        .with_cert_resolver(Arc::new(Resolver(Arc::new(
            tls::Ed25519Key::new(key).certified(),
        ))));
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    let connection = rustls::ServerConnection::new(Arc::new(config)).map_err(|e| e.to_string())?;
    let mut stream = rustls::StreamOwned::new(connection, tcp);
    while stream.conn.is_handshaking() {
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|e| e.to_string())?;
    }
    let peer = stream
        .conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|cert| tls::key_from_spki(cert.as_ref()))
        .ok_or("missing Client key")?;
    let hello: Hello = read_frame(&mut stream)?;
    if hello.schema_version != PROTOCOL || !crate::storage::label(&hello.name) {
        return Err("invalid Client hello".into());
    }
    let client = app
        .store
        .clients()?
        .into_iter()
        .find(|client| {
            client.id == hello.device_id
                && STANDARD
                    .decode(&client.public_key)
                    .is_ok_and(|stored| stored == peer)
        })
        .ok_or("Client trust missing")?;
    write_frame(
        &mut stream,
        &serde_json::json!({"schemaVersion":PROTOCOL,"connected":true,"accepts":[CHANGE_REPORT_FEATURE]}),
    )?;
    let id = client.id;
    let public_key = client.public_key;
    let session = Arc::new(Session {
        stream: Mutex::new(stream),
        next: AtomicU64::new(1),
        reported_name: hello.name,
        client_id: id.clone(),
        app: Arc::downgrade(&app),
    });
    app.tunnels
        .sessions
        .lock()
        .unwrap()
        .insert(id.clone(), session.clone());
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(10));
            if !app
                .tunnels
                .sessions
                .lock()
                .unwrap()
                .get(&id)
                .is_some_and(|current| Arc::ptr_eq(current, &session))
            {
                break;
            }
            if !app.store.clients().is_ok_and(|clients| {
                clients
                    .iter()
                    .any(|client| client.id == id && client.public_key == public_key)
            }) {
                break;
            }
            if session.exchange("GET", "/v1/ping", None).is_err() {
                break;
            }
        }
        app.tunnels.remove_if_same(&id, &session);
    });
    Ok(())
}

pub fn listen(app: Arc<App>, address: SocketAddr) -> Result<(), String> {
    let listener = TcpListener::bind(address)
        .map_err(|e| format!("cannot listen for Client tunnels on {address}: {e}"))?;
    let handshakes = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            if handshakes.fetch_add(1, Ordering::SeqCst) >= 32 {
                handshakes.fetch_sub(1, Ordering::SeqCst);
                continue;
            }
            let (app, handshakes) = (app.clone(), handshakes.clone());
            thread::spawn(move || {
                let _ = accept(app, tcp);
                handshakes.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{PublicIdentity, Store};
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    /// In-memory duplex: reads the scripted frames, records what is written.
    struct Duplex {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }
    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn frames(values: &[Value]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in values {
            write_frame(&mut bytes, value).unwrap();
        }
        bytes
    }

    #[test]
    fn client_requests_interleaved_with_a_reply_are_answered_then_the_reply_is_returned() {
        let mut duplex = Duplex {
            input: std::io::Cursor::new(frames(&[
                json!({"schemaVersion": PROTOCOL, "sequence": 7, "method": "POST", "path": CHANGE_REPORT_PATH, "body": {"x": 1}}),
                json!({"schemaVersion": PROTOCOL, "sequence": 3, "code": 200, "body": {"ok": true}}),
            ])),
            output: Vec::new(),
        };
        let mut seen = Vec::new();
        let reply = read_reply(&mut duplex, |request| {
            seen.push((
                request.method.clone(),
                request.path.clone(),
                request.body.clone(),
            ));
            Reply {
                code: 200,
                body: json!({"stored": true}),
            }
        })
        .unwrap();
        assert_eq!((reply.sequence, reply.code), (3, 200));
        assert_eq!(
            seen,
            vec![(
                "POST".into(),
                CHANGE_REPORT_PATH.into(),
                Some(json!({"x": 1}))
            )]
        );
        let answer: Value = read_frame(&mut std::io::Cursor::new(duplex.output)).unwrap();
        assert_eq!(
            answer,
            json!({"schemaVersion": PROTOCOL, "sequence": 7, "code": 200, "body": {"stored": true}})
        );
        // A malformed Client request closes the tunnel.
        let mut bad = Duplex {
            input: std::io::Cursor::new(frames(&[
                json!({"schemaVersion": "other", "sequence": 1, "method": "POST", "path": "/x", "body": null}),
            ])),
            output: Vec::new(),
        };
        assert!(read_reply(&mut bad, |_| Reply {
            code: 200,
            body: Value::Null
        })
        .is_err());
    }

    fn app_with_client() -> (Arc<App>, String) {
        let app = App::new(
            Store::memory(),
            crate::config::Settings {
                auth_mode: crate::config::AuthMode::Local,
                public_url: "http://localhost:3000".into(),
                google: None,
                local_operator_name: None,
                web_dir: None,
            },
        )
        .unwrap();
        app.store.generate("Server").unwrap();
        let key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let client = app
            .store
            .import(
                PublicIdentity {
                    schema_version: "baradwatchu.public-identity.v1".into(),
                    role: "client".into(),
                    algorithm: "Ed25519".into(),
                    public_key: STANDARD.encode(key),
                    id: None,
                    name: None,
                    fingerprint: None,
                    created_at_unix_ms: None,
                    executable_sha256: None,
                },
                "Workstation",
                &crate::storage::fingerprint(&key),
            )
            .unwrap();
        (app, client.id)
    }

    fn change(device: &str, id: &str, origin: &str) -> Value {
        json!({
            "schemaVersion": CHANGE_REPORT_SCHEMA,
            "reportId": id,
            "deviceId": device,
            "stateSha256": "a".repeat(64),
            "report": {"schemaVersion": "baradwatchu.audit.v1", "completedAtUnixMs": 5, "initiator": {"origin": origin},
                "policy": {"state": "APPLIED", "path": "/etc/baradwatchu/barad-policy.json", "sha256": "b".repeat(64)}, "results": []}
        })
    }

    #[test]
    fn change_reports_are_stored_once_for_every_administrator() {
        let (app, device) = app_with_client();
        let stored = receive_change_report(
            &app,
            &device,
            Some(change(&device, "auto-0001", "SCHEDULED")),
        );
        assert_eq!(stored.code, 200, "{:?}", stored.body);
        assert_eq!(stored.body["reportId"], "auto-0001");
        // Resent after a lost acknowledgement: same answer, one copy.
        assert_eq!(
            receive_change_report(
                &app,
                &device,
                Some(change(&device, "auto-0001", "SCHEDULED"))
            )
            .code,
            200
        );
        for operator in ["LOCAL", "https://accounts.google.com:123"] {
            let history = app.store.history(operator).unwrap();
            assert_eq!(history.len(), 1);
            assert_eq!(history[0]["automatic"], true);
            assert!(app
                .store
                .history_report(operator, "auto-0001")
                .unwrap()
                .is_some());
        }
        // Same ID, different content: refused.
        let mut changed = change(&device, "auto-0001", "SCHEDULED");
        changed["report"]["completedAtUnixMs"] = json!(6);
        assert_eq!(
            receive_change_report(&app, &device, Some(changed)).code,
            409
        );
    }

    #[test]
    fn change_reports_must_come_from_the_tunnel_client_and_be_periodic_audits() {
        let (app, device) = app_with_client();
        assert_eq!(receive_change_report(&app, &device, None).code, 400);
        assert_eq!(
            receive_change_report(
                &app,
                &device,
                Some(change("BWU-OTHER", "auto-0002", "SCHEDULED"))
            )
            .code,
            400
        );
        assert_eq!(
            receive_change_report(&app, &device, Some(change(&device, "auto-0003", "REMOTE"))).code,
            400
        );
        assert_eq!(
            receive_change_report(&app, &device, Some(change(&device, "x", "SCHEDULED"))).code,
            400
        );
        let mut broken = change(&device, "auto-0004", "SCHEDULED");
        broken["report"]["schemaVersion"] = json!("other");
        assert_eq!(receive_change_report(&app, &device, Some(broken)).code, 400);
        let mut extra = change(&device, "auto-0005", "SCHEDULED");
        extra["command"] = json!("run");
        assert_eq!(receive_change_report(&app, &device, Some(extra)).code, 400);
        assert_eq!(
            receive_change_report(
                &app,
                "BWU-UNKNOWN",
                Some(change("BWU-UNKNOWN", "auto-0006", "SCHEDULED"))
            )
            .code,
            403
        );
        assert!(app.store.history("LOCAL").unwrap().is_empty());
    }
}
