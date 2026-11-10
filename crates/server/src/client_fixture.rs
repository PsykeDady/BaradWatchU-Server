//! Isolated real Client process fixture, adapted from Client remote_service.rs.
#![allow(dead_code)]
use crate::storage as identity;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const SERVER_SEED: [u8; 32] = [11; 32];
const OTHER_SEED: [u8; 32] = [22; 32];

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub(crate) struct Fixture {
    pub(crate) root: PathBuf,
    service: Option<Child>,
    link: Option<Child>,
    tray: Option<Child>,
    pub(crate) address: SocketAddr,
    pub(crate) device_id: String,
    pub(crate) client_key: [u8; 32],
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for child in [&mut self.link, &mut self.tray, &mut self.service]
            .into_iter()
            .flatten()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn wait_until(what: &str, timeout: Duration, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn server_document(key: &SigningKey, name: &str) -> Value {
    let public = key.verifying_key().to_bytes();
    json!({
        "schemaVersion": "baradwatchu.public-identity.v1",
        "role": "server",
        "name": name,
        "algorithm": "Ed25519",
        "publicKey": base64::Engine::encode(&base64::engine::general_purpose::STANDARD,public),
        "fingerprint": identity::fingerprint(&public),
    })
}

impl Fixture {
    fn agent(&self) -> Command {
        let mut command = Command::new(
            std::env::var("BWU_CLIENT_BIN").expect("set BWU_CLIENT_BIN to the built Client agent"),
        );
        command
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .env("BARADWATCHU_SERVICE_DIR", self.root.join("service"))
            .env(
                "BARADWATCHU_SERVICE_SOCKET",
                self.root.join("sock/agent.sock"),
            )
            .env("LC_ALL", "en_US.UTF-8")
            .stdin(Stdio::null());
        command
    }

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let output = self.agent().args(args).output().unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    pub(crate) fn ok(&self, args: &[&str]) -> String {
        let (code, out, err) = self.run(args);
        assert_eq!(code, 0, "{args:?}: {out}{err}");
        out
    }

    /// Identity, one trusted Server, fast audit (built-in checks disabled), service with a
    /// loopback listener, remote requests enabled. No tray, no link yet.
    pub(crate) fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "bwu-remote-{label}-{}-{}",
            std::process::id(),
            now_ms() % 1_000_000
        ));
        std::fs::create_dir_all(root.join("config/baradwatchu")).unwrap();
        std::fs::write(
            root.join("config/baradwatchu/language.json"),
            r#"{"schemaVersion":"baradwatchu.language.v1","language":"english"}"#,
        )
        .unwrap();
        let mut fixture = Self {
            root,
            service: None,
            link: None,
            tray: None,
            address: "127.0.0.1:1".parse().unwrap(),
            device_id: String::new(),
            client_key: [0; 32],
        };
        fixture.ok(&["identity", "generate", "--yes"]);
        let export: Value = serde_json::from_str(&fixture.ok(&["identity", "export"])).unwrap();
        fixture.device_id = export["id"].as_str().unwrap().to_owned();
        fixture.client_key = serde_json::from_value::<identity::PublicIdentity>(export)
            .unwrap()
            .key("client")
            .unwrap();
        for n in 1..=9 {
            fixture.ok(&["disable", &format!("REQ-00{n}")]);
        }
        fixture.trust(&SigningKey::from_bytes(&SERVER_SEED), "Server Test");
        std::fs::create_dir_all(fixture.root.join("service")).unwrap();
        std::fs::write(
            fixture.root.join("service/service.json"),
            r#"{"schemaVersion":"baradwatchu.service-config.v1","remote":{"listen":"127.0.0.1:0"}}"#,
        )
        .unwrap();
        fixture.start_service();
        let out = fixture.ok(&["remote", "enable"]);
        assert!(out.contains(&fixture.device_id), "{out}");
        fixture
    }

    pub(crate) fn trust(&self, key: &SigningKey, name: &str) {
        let document = server_document(key, name);
        let file = self.root.join(format!("{name}.json").replace(' ', "-"));
        std::fs::write(&file, document.to_string()).unwrap();
        self.ok(&[
            "trust",
            "import",
            file.to_str().unwrap(),
            "--fingerprint",
            document["fingerprint"].as_str().unwrap(),
        ]);
    }

    fn status(&self) -> Value {
        serde_json::from_str(&self.ok(&["remote", "status", "--json"])).unwrap()
    }

    fn start_service(&mut self) {
        let child = self
            .agent()
            .args(["service", "run"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.service = Some(child);
        wait_until("service", Duration::from_secs(10), || {
            self.status()["serviceRunning"] == true
        });
        if let Some(address) = self.status()["service"]["listenerAddress"].as_str() {
            if self.status()["service"]["listenerRunning"] == true {
                self.address = address.parse().unwrap();
            }
        }
    }

    fn stop_service(&mut self) {
        if let Some(mut child) = self.service.take() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
    }

    /// A process whose name is `baradwatchu-tray`, recorded like the real tray does.
    pub(crate) fn start_tray(&mut self) {
        let fake = self.root.join("baradwatchu-tray");
        std::fs::copy("/usr/bin/sleep", &fake).unwrap();
        // A copy just written may be briefly "busy" while another test thread forks.
        let mut attempts = 0;
        let child = loop {
            match Command::new(&fake).arg("600").spawn() {
                Ok(child) => break child,
                Err(error) if error.raw_os_error() == Some(26) && attempts < 50 => {
                    attempts += 1;
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => panic!("{error}"),
            }
        };
        let dir = self.root.join("run/baradwatchu");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("tray.lock"), child.id().to_string()).unwrap();
        self.tray = Some(child);
    }

    pub(crate) fn start_link(&mut self) {
        let child = self
            .agent()
            .args(["remote", "link", "--watch-stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.link = Some(child);
        wait_until("link", Duration::from_secs(10), || {
            self.status()["service"]["sessionLinked"] == true
        });
    }

    fn stop_link(&mut self) {
        if let Some(mut child) = self.link.take() {
            drop(child.stdin.take()); // as when the tray exits
            wait_until("link exit", Duration::from_secs(10), || {
                child.try_wait().unwrap().is_some()
            });
        }
    }

    fn https(&self, key: &SigningKey, sni: &str, request: &str) -> Result<(u16, Value), String> {
        https_with(self.address, sni, self.client_key, key, request)
    }

    fn post(&self, key: &SigningKey, request_id: &str) -> (u16, Value) {
        let body = json!({
            "schemaVersion": "baradwatchu.remote-audit-request.v1",
            "requestId": request_id,
            "operation": "AUDIT_REPORT",
            "issuedAtUnixMs": now_ms(),
        })
        .to_string();
        self.https(key, &self.device_id, &post_request(&body))
            .unwrap()
    }

    fn get(&self, key: &SigningKey, path: &str) -> (u16, Value) {
        self.https(
            key,
            &self.device_id,
            &format!("GET {path} HTTP/1.1\r\nHost: client\r\n\r\n"),
        )
        .unwrap()
    }

    fn wait_state(&self, key: &SigningKey, id: &str, state: &str) -> Value {
        let mut last = Value::Null;
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            let (_, body) = self.get(key, &format!("/v1/audit-requests/{id}"));
            if body["state"] == state {
                return body;
            }
            last = body;
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("request {id} never reached {state}; last {last}");
    }

    fn consents(&self) -> Vec<Value> {
        let list: Value = serde_json::from_str(&self.ok(&["consent", "list", "--json"])).unwrap();
        list.as_array().unwrap().clone()
    }

    pub(crate) fn pending_remote(&self) -> Value {
        let mut found = None;
        wait_until("pending consent", Duration::from_secs(10), || {
            found = self
                .consents()
                .into_iter()
                .find(|c| c["state"] == "PENDING" && c["source"] == "REMOTE_SERVER");
            found.is_some()
        });
        found.unwrap()
    }
}

fn post_request(body: &str) -> String {
    format!(
        "POST /v1/audit-requests HTTP/1.1\r\nHost: client\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// The Server stand-in: one HTTP/1.1 exchange over mutual TLS.
fn https_with(
    address: SocketAddr,
    sni: &str,
    client_key: [u8; 32],
    key: &SigningKey,
    request: &str,
) -> Result<(u16, Value), String> {
    let config =
        crate::tls::requester_config(key.clone(), client_key).map_err(|e| e.to_string())?;
    let name = rustls::pki_types::ServerName::try_from(sni.to_ascii_lowercase())
        .map_err(|e| e.to_string())?;
    let connection = rustls::ClientConnection::new(config, name).map_err(|e| e.to_string())?;
    let tcp = TcpStream::connect(address).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut stream = rustls::StreamOwned::new(connection, tcp);
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8(response).map_err(|e| e.to_string())?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or("no HTTP response")?;
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("bad status line")?;
    Ok((status, serde_json::from_str(body).unwrap_or(Value::Null)))
}

fn server() -> SigningKey {
    SigningKey::from_bytes(&SERVER_SEED)
}
