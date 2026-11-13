//! Dashboard launch session, modelled on the Client `dashboard` command: a private runtime
//! record (`dashboard.json`) holds the port and random launch token, and the browser opens a
//! private `open-dashboard.html` so the token never appears on a process command line.
//! Namespace `baradwatchu-server` keeps it apart from a Client on the same host.
use crate::preferences::{atomic_bytes, atomic_json, ensure_private_dir};
use std::{
    fs,
    net::TcpStream,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

pub const SESSION_SCHEMA: &str = "baradwatchu-server.dashboard-session.v1";

#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Session {
    pub schema_version: String,
    pub pid: u32,
    /// Browser origin (`publicUrl`), e.g. `http://localhost:3000`.
    pub origin: String,
    pub port: u16,
    pub token: String,
}

impl Session {
    pub fn url(&self) -> String {
        format!("{}/?k={}", self.origin, self.token)
    }
}

/// `$XDG_RUNTIME_DIR/baradwatchu-server`, else `<data dir>/run` (Client: state/run fallback).
pub fn runtime_dir() -> Result<PathBuf, String> {
    let dir = match std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    {
        Some(base) => base.join("baradwatchu-server"),
        None => crate::config::data_dir()?.join("run"),
    };
    ensure_private_dir(&dir).map_err(|e| e.0)?;
    Ok(dir)
}

fn valid_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn read_session(dir: &Path) -> Option<Session> {
    let path = dir.join("dashboard.json");
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return None;
    }
    let session: Session = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    (session.schema_version == SESSION_SCHEMA && valid_token(&session.token)).then_some(session)
}

/// Reused only if the port accepts connections and, on Linux and macOS, the PID runs this
/// executable.
pub fn session_alive(session: &Session) -> bool {
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], session.port));
    if TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        let Ok(current) = std::env::current_exe().and_then(|p| p.canonicalize()) else {
            return false;
        };
        return fs::read_link(format!("/proc/{}/exe", session.pid)).is_ok_and(|exe| exe == current);
    }
    // macOS has no /proc: same check through proc_pidpath (Client dashboard.rs/events.rs).
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let Ok(current) = std::env::current_exe().and_then(|p| p.canonicalize()) else {
            return false;
        };
        let Ok(pid) = libc::c_int::try_from(session.pid) else {
            return false;
        };
        let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: the buffer is writable and its exact size is passed to the kernel.
        let length =
            unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        let Some(length) = usize::try_from(length).ok().filter(|length| *length > 0) else {
            return false;
        };
        buffer.truncate(length);
        return Path::new(std::ffi::OsStr::from_bytes(&buffer))
            .canonicalize()
            .is_ok_and(|exe| exe == current);
    }
    #[allow(unreachable_code)]
    true
}

pub fn write_session(dir: &Path, session: &Session) -> Result<(), String> {
    atomic_json(&dir.join("dashboard.json"), session).map_err(|e| e.0)
}

/// Remove the record at shutdown only while it still describes this process.
pub fn remove_session(dir: &Path) {
    if read_session(dir).is_some_and(|session| session.pid == std::process::id()) {
        let _ = fs::remove_file(dir.join("dashboard.json"));
        let _ = fs::remove_file(dir.join("open-dashboard.html"));
    }
}

fn launcher_html(url: &str) -> String {
    let language = baradwatchu_messages::configured_language().effective();
    let html_language = match language {
        baradwatchu_messages::Language::Italian => "it",
        _ => "en",
    };
    let label = baradwatchu_messages::message("cli.dashboard.open_link", language);
    format!("<!doctype html><html lang=\"{html_language}\"><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><meta http-equiv=\"refresh\" content=\"0;url={url}\"><title>BaradWatchU Server</title></head><body><p><a href=\"{url}\">{label}</a></p></body></html>\n")
}

/// Open `url` through a private launcher file when a graphical session exists.
pub fn open_in_browser(dir: &Path, url: &str) {
    let launcher = dir.join("open-dashboard.html");
    if atomic_bytes(&launcher, launcher_html(url).as_bytes()).is_err() {
        return;
    }
    let opener = Path::new(if cfg!(target_os = "macos") {
        "/usr/bin/open"
    } else {
        "/usr/bin/xdg-open"
    });
    let graphical = cfg!(target_os = "macos")
        || std::env::var_os("WAYLAND_DISPLAY").is_some()
        || std::env::var_os("DISPLAY").is_some();
    if graphical && opener.is_file() {
        let _ = Command::new(opener)
            .arg(&launcher)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|mut child| std::thread::spawn(move || child.wait()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bwu-launcher-{}",
            crate::storage::random().unwrap()
        ));
        ensure_private_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn session_record_is_private_validated_and_removed_only_by_its_owner() {
        let dir = temp_dir();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let session = Session {
            schema_version: SESSION_SCHEMA.into(),
            pid: std::process::id(),
            origin: format!("http://localhost:{port}"),
            port,
            token: "a".repeat(64),
        };
        write_session(&dir, &session).unwrap();
        let file = dir.join("dashboard.json");
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(read_session(&dir).as_ref(), Some(&session));
        assert_eq!(
            session.url(),
            format!("http://localhost:{port}/?k={}", "a".repeat(64))
        );
        // Port open and PID = this executable: alive; closed port: stale.
        assert!(session_alive(&session));
        drop(listener);
        assert!(!session_alive(&session));
        // Foreign/invalid records are ignored and never removed.
        let foreign = Session { pid: 1, ..session };
        write_session(&dir, &foreign).unwrap();
        remove_session(&dir);
        assert!(file.exists());
        fs::write(
            &file,
            r#"{"schemaVersion":"baradwatchu.dashboard-session.v1","pid":1,"port":1,"token":"x"}"#,
        )
        .unwrap();
        assert!(read_session(&dir).is_none());
        let own = Session {
            pid: std::process::id(),
            ..foreign
        };
        write_session(&dir, &own).unwrap();
        remove_session(&dir);
        assert!(!file.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn launcher_keeps_token_off_the_command_line() {
        let html = launcher_html("http://localhost:3000/?k=abc");
        assert!(html.contains("url=http://localhost:3000/?k=abc"));
        assert!(html.contains("no-referrer"));
    }
}
