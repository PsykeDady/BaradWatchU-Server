//! One HTTP request per pinned, mutually authenticated TLS 1.3 connection.
use crate::{
    storage::{Result, TrustedClient},
    tls,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use std::{
    io::{Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

const LIMIT: usize = 8 * 1024 * 1024;
#[derive(Debug)]
pub struct Reply {
    pub code: u16,
    pub body: serde_json::Value,
}
pub async fn request(
    key: SigningKey,
    client: TrustedClient,
    method: &'static str,
    path: String,
    body: Option<serde_json::Value>,
) -> Result<Reply> {
    tokio::task::spawn_blocking(move || exchange(key, &client, method, &path, body))
        .await
        .map_err(|_| "remote worker failed")?
}
fn exchange(
    key: SigningKey,
    client: &TrustedClient,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<Reply> {
    let addr = client
        .endpoint
        .parse()
        .map_err(|_| "invalid registered endpoint")?;
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|_| "CLIENT_UNREACHABLE")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let public: [u8; 32] = STANDARD
        .decode(&client.public_key)
        .map_err(|_| "invalid trusted key")?
        .try_into()
        .map_err(|_| "invalid trusted key")?;
    let config = tls::requester_config(key, public).map_err(|_| "TLS configuration failed")?;
    let name = rustls::pki_types::ServerName::try_from(client.id.clone())
        .map_err(|_| "invalid Client ID")?;
    let conn =
        rustls::ClientConnection::new(config, name).map_err(|_| "TLS initialization failed")?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    let body = body.map(|v| v.to_string()).unwrap_or_default();
    let request=format!("{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",client.id,body.len());
    tls.write_all(request.as_bytes())
        .map_err(|_| "TLS_OR_CONNECTION_FAILED")?;
    tls.flush().map_err(|_| "TLS_OR_CONNECTION_FAILED")?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut bytes = Vec::new();
    let mut buf = [0; 8192];
    loop {
        if Instant::now() > deadline {
            return Err("CLIENT_RESPONSE_TIMEOUT".into());
        }
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                bytes.extend_from_slice(&buf[..n]);
                if bytes.len() > LIMIT {
                    return Err("CLIENT_RESPONSE_TOO_LARGE".into());
                }
                if let Some((offset, length, _)) = headers(&bytes)? {
                    if bytes.len() >= offset + length {
                        break;
                    }
                }
            }
            Err(_) => return Err("TLS_OR_CONNECTION_FAILED".into()),
        }
    }
    parse_reply(&bytes)
}
fn headers(bytes: &[u8]) -> Result<Option<(usize, usize, u16)>> {
    let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") else {
        if bytes.len() > 16384 {
            return Err("invalid remote headers".into());
        }
        return Ok(None);
    };
    if end > 16384 {
        return Err("invalid remote headers".into());
    }
    let text = std::str::from_utf8(&bytes[..end]).map_err(|_| "invalid remote headers")?;
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let mut parts = status.split_whitespace();
    if parts.next() != Some("HTTP/1.1") {
        return Err("invalid remote HTTP version".into());
    }
    let code = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|n| (100..600).contains(n))
        .ok_or("invalid remote status")?;
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("invalid remote header")?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("unsupported transfer encoding".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("duplicate content length".into());
            }
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid content length")?,
            );
        }
    }
    let length = length.ok_or("missing remote content length")?;
    if length > LIMIT - 16384 {
        return Err("remote response too large".into());
    }
    Ok(Some((end + 4, length, code)))
}
fn parse_reply(bytes: &[u8]) -> Result<Reply> {
    let (offset, length, code) = headers(bytes)?.ok_or("incomplete remote headers")?;
    if bytes.len() != offset + length {
        return Err("incomplete or excessive remote response".into());
    }
    let body = serde_json::from_slice(&bytes[offset..]).map_err(|_| "invalid remote JSON")?;
    Ok(Reply { code, body })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_http_framing() {
        assert_eq!(
            parse_reply(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .unwrap()
                .code,
            200
        );
        for b in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{}",
        ] {
            assert!(parse_reply(b).is_err());
        }
    }
}
