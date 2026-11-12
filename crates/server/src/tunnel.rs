//! Outbound Client connections. The dashboard never accepts network authentication here.
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
        let reply: ResponseFrame = read_frame(&mut *stream)?;
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
        &serde_json::json!({"schemaVersion":PROTOCOL,"connected":true}),
    )?;
    let id = client.id;
    let public_key = client.public_key;
    let session = Arc::new(Session {
        stream: Mutex::new(stream),
        next: AtomicU64::new(1),
        reported_name: hello.name,
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
